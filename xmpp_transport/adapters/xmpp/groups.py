"""Xabber Groups protocol adapter for transport-owned conversations."""

import logging
from typing import Protocol
from xml.etree import ElementTree as ET

from xmpp_transport.domain.identifiers import BindingId
from xmpp_transport.domain.models import Conversation
from xmpp_transport.ports.repositories import BindingRepository

from .namespaces import GROUPS_NS, NICK_NS, PUBSUB_AVATAR_METADATA_NS, STANZAS_NS


log = logging.getLogger(__name__)

GROUP_AVATAR_MAX_BYTES = 524288


class GroupWire(Protocol):
    async def request(self, element: ET.Element, timeout: float = 10.0) -> ET.Element:
        ...

    async def send(self, element: ET.Element) -> None:
        ...


class XmppGroupManager:
    def __init__(
        self,
        wire: GroupWire,
        bindings: BindingRepository,
        component_domain: str,
        server_domain: str,
        control_localpart: str,
        group_localpart_prefix: str,
        provider_label: str,
    ) -> None:
        self._wire = wire
        self._bindings = bindings
        self._component_domain = component_domain
        self._server_domain = server_domain
        self._control_jid = "{}@{}".format(control_localpart, component_domain)
        self._group_localpart_prefix = group_localpart_prefix
        self._provider_label = provider_label
        self._ensured_members = set()
        self._ensured_groups = {}

    async def ensure_group(
        self, binding_id: BindingId, conversation: Conversation
    ) -> None:
        owner_jid = await self._bindings.xmpp_account_for_binding(binding_id)
        if owner_jid is None:
            raise LookupError("active XMPP account not found for group synchronization")
        localpart = self._group_localpart(owner_jid, str(conversation.id))
        group_jid = "{}@{}".format(localpart, self._server_domain)
        signature = (
            conversation.title,
            self._avatar_signature(conversation),
            tuple(
                (str(participant.id), participant.display_name)
                for participant in conversation.participants
            ),
        )
        if self._ensured_groups.get((owner_jid, group_jid)) == signature:
            return
        create = ET.Element("{{{}}}create".format(GROUPS_NS))
        group = ET.SubElement(create, "group", {"privacy": "public"})
        ET.SubElement(group, "localpart").text = localpart
        info = ET.SubElement(group, "info")
        ET.SubElement(info, "name").text = conversation.title
        ET.SubElement(info, "description").text = "{} group {}".format(
            self._provider_label, conversation.id
        )
        settings = ET.SubElement(group, "settings")
        ET.SubElement(settings, "index").text = "none"
        ET.SubElement(settings, "membership").text = "private"
        try:
            await self._request(self._server_domain, create)
        except Exception as exc:
            if not self._is_conflict(exc):
                raise
        # The group creator is already a member.  The original transports do
        # not update info or invite the component after create/conflict: both
        # requests can be rejected when an existing group is restored.
        await self._ensure_owner_invitation(owner_jid, group_jid, conversation)
        if conversation.avatar is not None:
            try:
                await self._update_avatar(group_jid, conversation)
            except Exception as exc:
                rejection = self._iq_rejection(exc)
                if rejection is not None:
                    code, condition = rejection
                    log.warning(
                        "XEP-GROUPS avatar update rejected; continuing group sync "
                        "binding_id=%s group_jid=%s code=%s condition=%s",
                        binding_id,
                        group_jid,
                        code,
                        condition,
                    )
                else:
                    log.warning(
                        "XEP-GROUPS avatar update failed; continuing group sync "
                        "binding_id=%s group_jid=%s",
                        binding_id,
                        group_jid,
                        exc_info=True,
                    )
        owner_remote_id = conversation.attributes.get("owner_remote_id")
        for participant in conversation.participants:
            if owner_remote_id and str(participant.id) == owner_remote_id:
                continue
            member_jid = self._member_jid(owner_remote_id, str(participant.id))
            await self._ensure_member(
                owner_jid,
                group_jid,
                member_jid,
                participant.display_name
                or "{} user {}".format(self._provider_label, participant.id),
                auto_join=True,
            )
        self._ensured_groups[(owner_jid, group_jid)] = signature

    async def _ensure_owner_invitation(
        self, owner_jid: str, group_jid: str, conversation: Conversation
    ) -> None:
        key = (owner_jid, group_jid, owner_jid)
        if key in self._ensured_members:
            return
        invite = ET.Element("{{{}}}invite".format(GROUPS_NS))
        ET.SubElement(invite, "jid").text = owner_jid
        ET.SubElement(invite, "send").text = "false"
        ET.SubElement(invite, "reason").text = "{} group member".format(
            self._provider_label
        )
        try:
            await self._request(group_jid, invite)
        except Exception as exc:
            # An earlier server-side invitation may have created the pending
            # invitation before its notification failed.
            if not self._is_conflict(exc):
                raise
        message = ET.Element(
            "message",
            {"type": "chat", "from": self._control_jid, "to": owner_jid},
        )
        direct_invite = ET.SubElement(
            message, "{{{}}}invite".format(GROUPS_NS), {"jid": group_jid}
        )
        ET.SubElement(direct_invite, "reason").text = "{} group member".format(
            self._provider_label
        )
        group = ET.SubElement(
            message,
            "{{{}}}group".format(GROUPS_NS),
            {"jid": group_jid, "privacy": "public"},
        )
        info = ET.SubElement(group, "info")
        ET.SubElement(info, "name").text = conversation.title
        ET.SubElement(message, "body").text = (
            "To join the group chat, add {} to your contact list.".format(group_jid)
        )
        await self._wire.send(message)
        self._ensured_members.add(key)

    async def _update_avatar(
        self, group_jid: str, conversation: Conversation
    ) -> None:
        avatar = conversation.avatar
        if avatar is None:
            return
        avatar_id = avatar.version or avatar.reference
        info = ET.Element("{{{}}}info".format(GROUPS_NS))
        avatar_element = ET.SubElement(info, "avatar")
        ET.SubElement(
            avatar_element,
            "{{{}}}info".format(PUBSUB_AVATAR_METADATA_NS),
            {
                "bytes": str(avatar.size if avatar.size > 0 else GROUP_AVATAR_MAX_BYTES),
                "id": avatar_id,
                "type": avatar.content_type,
                "url": avatar.reference,
            },
        )
        await self._request(group_jid, info)

    @staticmethod
    def _avatar_signature(conversation: Conversation):  # type: ignore[no-untyped-def]
        avatar = conversation.avatar
        if avatar is None:
            return None
        return (avatar.version, avatar.reference, avatar.content_type, avatar.size)

    async def _ensure_member(
        self,
        owner_jid: str,
        group_jid: str,
        member_jid: str,
        nickname: str,
        *,
        auto_join: bool,
    ) -> None:
        key = (owner_jid, group_jid, member_jid)
        if key in self._ensured_members:
            return
        invite = ET.Element("{{{}}}invite".format(GROUPS_NS))
        ET.SubElement(invite, "jid").text = member_jid
        ET.SubElement(invite, "send").text = "false"
        ET.SubElement(invite, "reason").text = "{} group member".format(
            self._provider_label
        )
        invited = True
        try:
            await self._request(group_jid, invite)
        except Exception:
            invited = False
        if not auto_join:
            if invited:
                self._ensured_members.add(key)
            return
        subscribe = ET.Element(
            "presence",
            {"from": member_jid, "to": group_jid, "type": "subscribe"},
        )
        ET.SubElement(subscribe, "{{{}}}nick".format(NICK_NS)).text = nickname
        await self._wire.send(subscribe)
        subscribed = ET.Element(
            "presence",
            {"from": member_jid, "to": group_jid, "type": "subscribed"},
        )
        await self._wire.send(subscribed)
        self._ensured_members.add(key)

    def _member_jid(self, owner_remote_id: str, member_remote_id: str) -> str:
        try:
            localpart = "chat-{}".format(
                int(owner_remote_id) ^ int(member_remote_id)
            )
        except (TypeError, ValueError):
            safe = "".join(
                character
                for character in member_remote_id
                if character.isalnum() or character in "-_"
            ) or "unknown"
            localpart = "{}-user-{}".format(self._provider_label.lower(), safe)
        return "{}@{}".format(localpart, self._component_domain)

    async def _request(self, recipient: str, payload: ET.Element) -> ET.Element:
        iq = ET.Element(
            "iq",
            {"type": "set", "from": self._control_jid, "to": recipient},
        )
        iq.append(payload)
        return await self._wire.request(iq)

    def _group_localpart(self, owner_jid: str, conversation_id: str) -> str:
        token = "".join(
            character
            for character in conversation_id
            if character.isalnum() or character in "-_"
        ) or "unknown"
        return "{}-{}-{}".format(
            self._group_localpart_prefix,
            owner_jid.encode("utf-8").hex(),
            token,
        )

    @staticmethod
    def _is_conflict(exc: Exception) -> bool:
        iq = getattr(exc, "iq", None)
        xml = getattr(iq, "xml", None)
        return xml is not None and xml.find(
            ".//{{{}}}conflict".format(STANZAS_NS)
        ) is not None

    @staticmethod
    def _iq_rejection(exc: Exception):  # type: ignore[no-untyped-def]
        iq = getattr(exc, "iq", None)
        xml = getattr(iq, "xml", None)
        if xml is None:
            return None
        error = xml.find("error")
        if error is None:
            error = xml.find("{jabber:client}error")
        if error is None:
            return None
        code = error.attrib.get("code") or "unknown"
        conditions = tuple(
            child.tag.rsplit("}", 1)[-1]
            for child in error
            if child.tag.startswith("{{{}}}".format(STANZAS_NS))
            and child.tag.rsplit("}", 1)[-1] != "text"
        )
        condition = conditions[0] if conditions else "unknown"
        return code, condition
