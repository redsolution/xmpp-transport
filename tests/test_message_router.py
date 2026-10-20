import asyncio
import unittest
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple, Type, TypeVar

from xmpp_transport.application.message_router import MessageRouter
from xmpp_transport.domain.errors import FeatureUnavailable
from xmpp_transport.domain.events import EventEnvelope, MessageReceived
from xmpp_transport.domain.identifiers import BackendId, BindingId, EventId, RemoteObjectId
from xmpp_transport.domain.models import (
    ForwardReference,
    IncomingMessage,
    MessageButton,
    OutgoingMessage,
    ReplyReference,
)
from xmpp_transport.ports.backend import ButtonActions, MessageSender, SendResult


FeatureT = TypeVar("FeatureT")


class FakeFeatures:
    def __init__(self) -> None:
        self.values: Dict[Tuple[BindingId, type], object] = {}

    async def feature(
        self, binding_id: BindingId, feature_type: Type[FeatureT]
    ) -> Optional[FeatureT]:
        return self.values.get((binding_id, feature_type))  # type: ignore[return-value]


class FakeMappings:
    def __init__(self) -> None:
        self.outgoing: Dict[Tuple[BindingId, str], RemoteObjectId] = {}
        self.incoming = set()

    async def remote_id_for_client_message(
        self, binding_id: BindingId, client_message_id: str
    ) -> Optional[RemoteObjectId]:
        return self.outgoing.get((binding_id, client_message_id))

    async def save_mapping(
        self,
        binding_id: BindingId,
        client_message_id: str,
        remote_message_id: RemoteObjectId,
    ) -> None:
        self.outgoing[(binding_id, client_message_id)] = remote_message_id

    async def incoming_delivered(
        self, binding_id: BindingId, remote_message_id: RemoteObjectId
    ) -> bool:
        return (binding_id, remote_message_id) in self.incoming

    async def mark_incoming_delivered(
        self, binding_id: BindingId, remote_message_id: RemoteObjectId
    ) -> None:
        self.incoming.add((binding_id, remote_message_id))


class FakeSender:
    def __init__(self) -> None:
        self.calls = 0
        self.messages = []

    async def send_message(self, message: OutgoingMessage) -> SendResult:
        self.calls += 1
        self.messages.append(message)
        await asyncio.sleep(0)
        return SendResult(RemoteObjectId("remote-{}".format(message.client_message_id)))


class FakeButtonActions:
    def __init__(self) -> None:
        self.calls = []

    async def activate_button(
        self, conversation_id, callback_id, payload, button_type  # type: ignore[no-untyped-def]
    ) -> None:
        self.calls.append((conversation_id, callback_id, payload, button_type))


class FakeXmpp:
    def __init__(self) -> None:
        self.delivered = []
        self.fail = False

    async def deliver_message(self, message: IncomingMessage) -> None:
        if self.fail:
            raise ConnectionError("xmpp unavailable")
        self.delivered.append(message)


def incoming_event(binding_id: BindingId, remote_id: str = "remote-1") -> MessageReceived:
    message = IncomingMessage(
        id=RemoteObjectId(remote_id),
        binding_id=binding_id,
        conversation_id=RemoteObjectId("conversation-1"),
        sender_id=RemoteObjectId("sender-1"),
        occurred_at=datetime.now(timezone.utc),
        text="hello",
    )
    return MessageReceived(
        envelope=EventEnvelope(
            event_id=EventId("event-" + remote_id),
            event_type="message.received",
            schema_version=1,
            backend_id=BackendId("fake"),
            binding_id=binding_id,
            occurred_at=message.occurred_at,
        ),
        message=message,
    )


class MessageRouterTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.binding_id = BindingId("binding-1")
        self.features = FakeFeatures()
        self.mappings = FakeMappings()
        self.xmpp = FakeXmpp()
        self.router = MessageRouter(self.features, self.mappings, self.xmpp)

    async def test_concurrent_duplicate_outgoing_message_is_sent_once(self) -> None:
        sender = FakeSender()
        self.features.values[(self.binding_id, MessageSender)] = sender
        message = OutgoingMessage(
            client_message_id="client-1",
            binding_id=self.binding_id,
            conversation_id=RemoteObjectId("conversation-1"),
            text="hello",
        )
        first, second = await asyncio.gather(
            self.router.send(message), self.router.send(message)
        )
        self.assertEqual(1, sender.calls)
        self.assertEqual(first, second)

    async def test_existing_mapping_does_not_require_active_sender(self) -> None:
        self.mappings.outgoing[(self.binding_id, "client-1")] = RemoteObjectId("remote-1")
        result = await self.router.send(
            OutgoingMessage(
                client_message_id="client-1",
                binding_id=self.binding_id,
                conversation_id=RemoteObjectId("conversation-1"),
                text="hello",
            )
        )
        self.assertEqual(RemoteObjectId("remote-1"), result.remote_message_id)

    async def test_own_forward_resolves_xabber_id_to_provider_message_id(self) -> None:
        sender = FakeSender()
        self.features.values[(self.binding_id, MessageSender)] = sender
        self.mappings.outgoing[(self.binding_id, "original-client-id")] = RemoteObjectId(
            "116974846586354125"
        )
        await self.router.send(
            OutgoingMessage(
                client_message_id="forward-1", binding_id=self.binding_id,
                conversation_id=RemoteObjectId("22"),
                forwarded_from=ForwardReference(
                    source_name="user@example.com",
                    source_recipient="chat-11@max.example.com",
                    source_message_id=RemoteObjectId("server-copy-id"),
                    source_message_ids=(RemoteObjectId("server-copy-id"),
                                        RemoteObjectId("original-client-id")),
                    body="Own message", is_self=True,
                ),
            )
        )
        self.assertEqual(
            RemoteObjectId("116974846586354125"),
            sender.messages[0].forwarded_from.source_message_id,
        )
        self.assertEqual("Own message", sender.messages[0].forwarded_from.body)

    async def test_own_forward_keeps_provider_id_when_no_xabber_mapping_exists(self) -> None:
        sender = FakeSender()
        self.features.values[(self.binding_id, MessageSender)] = sender
        await self.router.send(
            OutgoingMessage(
                client_message_id="forward-2", binding_id=self.binding_id,
                conversation_id=RemoteObjectId("22"),
                forwarded_from=ForwardReference(
                    source_name="user@example.com",
                    source_recipient="chat-11@max.example.com",
                    source_message_id=RemoteObjectId("116974846586354125"),
                    source_message_ids=(RemoteObjectId("client-id"),
                                        RemoteObjectId("116974846586354125")),
                    body="Own message from MAX", is_self=True,
                ),
            )
        )
        self.assertEqual(
            RemoteObjectId("116974846586354125"),
            sender.messages[0].forwarded_from.source_message_id,
        )

    async def test_reply_resolves_xabber_origin_id_to_provider_message_id(self) -> None:
        sender = FakeSender()
        self.features.values[(self.binding_id, MessageSender)] = sender
        self.mappings.outgoing[(self.binding_id, "client-1")] = RemoteObjectId("max-1")

        await self.router.send(
            OutgoingMessage(
                client_message_id="reply-1", binding_id=self.binding_id,
                conversation_id=RemoteObjectId("11"), text="response",
                reply_to=ReplyReference(
                    RemoteObjectId("archive-1"),
                    candidate_ids=(RemoteObjectId("client-1"), RemoteObjectId("archive-1")),
                ),
            )
        )

        self.assertEqual(RemoteObjectId("max-1"), sender.messages[0].reply_to.message_id)
        self.assertEqual("response", sender.messages[0].text)

    async def test_missing_sender_feature_is_reported(self) -> None:
        with self.assertRaises(FeatureUnavailable):
            await self.router.send(
                OutgoingMessage(
                    client_message_id="client-1",
                    binding_id=self.binding_id,
                    conversation_id=RemoteObjectId("conversation-1"),
                    text="hello",
                )
            )

    async def test_duplicate_incoming_message_is_delivered_once(self) -> None:
        event = incoming_event(self.binding_id)
        first, second = await asyncio.gather(
            self.router.receive(event), self.router.receive(event)
        )
        self.assertEqual([True, False], [first, second])
        self.assertEqual(1, len(self.xmpp.delivered))

    async def test_failed_xmpp_delivery_is_not_marked_delivered(self) -> None:
        event = incoming_event(self.binding_id)
        self.xmpp.fail = True
        with self.assertRaises(ConnectionError):
            await self.router.receive(event)
        self.xmpp.fail = False
        self.assertTrue(await self.router.receive(event))
        self.assertEqual(1, len(self.xmpp.delivered))

    async def test_message_binding_must_match_envelope(self) -> None:
        event = incoming_event(self.binding_id)
        mismatched = MessageReceived(
            envelope=EventEnvelope(
                event_id=event.envelope.event_id,
                event_type=event.envelope.event_type,
                schema_version=event.envelope.schema_version,
                backend_id=event.envelope.backend_id,
                binding_id=BindingId("other-binding"),
                occurred_at=event.envelope.occurred_at,
            ),
            message=event.message,
        )
        with self.assertRaises(ValueError):
            await self.router.receive(mismatched)

    async def test_remembers_incoming_button_and_activates_callback(self) -> None:
        actions = FakeButtonActions()
        self.features.values[(self.binding_id, ButtonActions)] = actions
        event = incoming_event(self.binding_id)
        event = MessageReceived(
            event.envelope,
            IncomingMessage(
                **{
                    **event.message.__dict__,
                    "buttons": ((MessageButton("OK", "confirm", "callback-1"),),),
                }
            ),
        )

        await self.router.receive(event)
        activated = await self.router.activate_button(
            self.binding_id, RemoteObjectId("conversation-1"), "/confirm"
        )

        self.assertTrue(activated)
        self.assertEqual(
            [(RemoteObjectId("conversation-1"), "callback-1", "confirm", "CALLBACK")],
            actions.calls,
        )


if __name__ == "__main__":
    unittest.main()
