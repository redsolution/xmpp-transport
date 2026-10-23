import asyncio
import ssl
import unittest
from xml.etree import ElementTree as ET

from xmpp_transport.adapters.xmpp.component import ComponentSettings, SlixmppComponentWire
from xmpp_transport.adapters.xmpp.namespaces import FILES_NS, XABBER_REFERENCES_NS


class FakeStanza:
    def __init__(self, attributes, body):  # type: ignore[no-untyped-def]
        self.xml = ET.Element("{jabber:component:accept}message", attributes)
        if body is not None:
            ET.SubElement(self.xml, "{jabber:component:accept}body").text = body
        self.sent = False

    def send(self) -> None:
        self.sent = True


class FakeClient:
    def __init__(self) -> None:
        self.message = None
        self.raw = []

    def make_message(self, *, mfrom, mto, mtype, mbody):  # type: ignore[no-untyped-def]
        attributes = {"from": mfrom, "to": mto, "type": mtype}
        self.message = FakeStanza(attributes, mbody)
        return self.message

    def send_raw(self, value: str) -> None:
        self.raw.append(value)


class ConnectingClient(FakeClient):
    def __init__(self, connect_result=True, *, tls_active=False) -> None:  # type: ignore[no-untyped-def]
        super().__init__()
        self.connect_result = connect_result
        self.handlers = {}
        self.disconnected = 0
        self.cancelled_attempts = 0
        self.aborted = 0
        self.starttls_services = set()
        self.transport = FakeTransport(tls_active)

    def add_event_handler(self, name, handler) -> None:  # type: ignore[no-untyped-def]
        self.handlers[name] = handler

    def connect(self):  # type: ignore[no-untyped-def]
        if self.connect_result is True:
            asyncio.get_running_loop().call_soon(
                lambda: asyncio.create_task(self.handlers["session_start"](None))
            )
        return self.connect_result

    def disconnect(self) -> None:
        self.disconnected += 1

    def cancel_connection_attempt(self) -> None:
        self.cancelled_attempts += 1

    def abort(self) -> None:
        self.aborted += 1

    def lose_connection(self) -> None:
        self.handlers["disconnected"](None)


class FakeTransport:
    def __init__(self, tls_active: bool) -> None:
        self.tls_active = tls_active

    def get_extra_info(self, name: str):  # type: ignore[no-untyped-def]
        return object() if name == "ssl_object" and self.tls_active else None


class SlixmppComponentWireTests(unittest.IsolatedAsyncioTestCase):
    async def test_direct_tls_uses_server_name_without_plaintext_fallback(self) -> None:
        from slixmpp import ComponentXMPP

        settings = ComponentSettings(
            "max.example", "secret", host="127.0.0.1", port=5237,
            tls=True, tls_server_name="xmpp.example.com",
        )
        wire = SlixmppComponentWire(settings)
        client = ComponentXMPP(settings.domain, settings.secret, settings.host, settings.port)
        wire._configure_tls(client)

        self.assertTrue(client.enable_direct_tls)
        self.assertFalse(client.enable_starttls)
        self.assertFalse(client.enable_plaintext)
        self.assertEqual("xmpp.example.com", client.default_domain)
        self.assertTrue(client.ssl_context.check_hostname)
        self.assertEqual(ssl.CERT_REQUIRED, client.ssl_context.verify_mode)

        attempts = []
        successful = [True]

        async def attempt(host, port, tls, server_name):  # type: ignore[no-untyped-def]
            attempts.append((host, port, tls, server_name))
            return successful[0]

        client.custom_address = (settings.host, settings.port)
        client._attempt_connection = attempt
        await client._connect_loop()
        self.assertEqual(
            [("127.0.0.1", 5237, True, "xmpp.example.com")], attempts
        )
        attempts.clear()
        successful[0] = False
        await client._connect_loop()
        self.assertEqual(
            [("127.0.0.1", 5237, True, "xmpp.example.com")], attempts
        )

    async def test_tls_requires_certificate_name(self) -> None:
        with self.assertRaisesRegex(ValueError, "tls_server_name"):
            ComponentSettings("max.example", "secret", tls=True)

    async def test_tls_session_is_ready_only_after_verified_transport(self) -> None:
        clients = []

        def factory(*args):  # type: ignore[no-untyped-def]
            client = ConnectingClient(tls_active=bool(clients))
            clients.append(client)
            return client

        wire = SlixmppComponentWire(
            ComponentSettings(
                "max.example", "secret", connect_timeout=0.02,
                reconnect_delay=0.01, tls=True,
                tls_server_name="xmpp.example.com",
            ),
            client_factory=factory,
        )
        wire.set_message_handler(lambda stanza: asyncio.sleep(0))

        await asyncio.wait_for(wire.start(), timeout=0.5)

        self.assertEqual(2, len(clients))
        self.assertEqual(1, clients[0].aborted)
        self.assertEqual(1, clients[0].disconnected)
        self.assertEqual(0, clients[1].aborted)
        for client in clients:
            self.assertTrue(client.enable_direct_tls)
            self.assertFalse(client.enable_plaintext)
            self.assertFalse(client.enable_starttls)
            self.assertEqual("xmpp.example.com", client.default_domain)
            self.assertEqual(ssl.CERT_REQUIRED, client.ssl_context.verify_mode)
        clients[0].lose_connection()
        self.assertTrue(wire._ready.is_set())
        await wire.close()

    async def test_tls_send_and_request_reject_unencrypted_transport(self) -> None:
        wire = SlixmppComponentWire(
            ComponentSettings(
                "max.example", "secret", tls=True,
                tls_server_name="xmpp.example.com",
            )
        )
        client = ConnectingClient(tls_active=False)
        wire._client = client
        wire._ready = asyncio.Event()
        wire._ready.set()

        with self.assertRaises(ConnectionError):
            await wire.send(ET.Element("message"))
        self.assertIsNone(client.message)
        wire._ready.set()
        with self.assertRaises(ConnectionError):
            await wire.request(ET.Element("iq", {"type": "set"}))
        self.assertFalse(wire._ready.is_set())

    async def test_retries_initial_connection_failure(self) -> None:
        clients = []

        def factory(*args):  # type: ignore[no-untyped-def]
            client = ConnectingClient(False if not clients else True)
            clients.append(client)
            return client

        wire = SlixmppComponentWire(
            ComponentSettings(
                "max.example", "secret", connect_timeout=0.05, reconnect_delay=0.01
            ),
            client_factory=factory,
        )
        wire.set_message_handler(lambda stanza: asyncio.sleep(0))

        await asyncio.wait_for(wire.start(), timeout=0.5)

        self.assertEqual(2, len(clients))
        self.assertGreaterEqual(clients[0].disconnected, 1)
        self.assertEqual(1, clients[0].cancelled_attempts)
        await wire.close()

    async def test_cancels_background_connection_after_session_timeout(self) -> None:
        clients = []

        def factory(*args):  # type: ignore[no-untyped-def]
            client = ConnectingClient(None if not clients else True)
            clients.append(client)
            return client

        wire = SlixmppComponentWire(
            ComponentSettings(
                "max.example", "secret", connect_timeout=0.02, reconnect_delay=0.01
            ),
            client_factory=factory,
        )
        wire.set_message_handler(lambda stanza: asyncio.sleep(0))

        await asyncio.wait_for(wire.start(), timeout=0.5)

        self.assertEqual(2, len(clients))
        self.assertEqual(1, clients[0].cancelled_attempts)
        self.assertEqual(1, clients[0].disconnected)
        await wire.close()

    async def test_reconnects_after_disconnect(self) -> None:
        clients = []

        def factory(*args):  # type: ignore[no-untyped-def]
            client = ConnectingClient()
            clients.append(client)
            return client

        wire = SlixmppComponentWire(
            ComponentSettings(
                "max.example", "secret", connect_timeout=0.05, reconnect_delay=0.01
            ),
            client_factory=factory,
        )
        wire.set_message_handler(lambda stanza: asyncio.sleep(0))
        await wire.start()

        clients[0].lose_connection()
        for _attempt in range(20):
            if len(clients) >= 2:
                break
            await asyncio.sleep(0.01)

        self.assertEqual(2, len(clients))
        await wire.close()

    async def test_sends_message_through_slixmpp_stanza_api(self) -> None:
        wire = SlixmppComponentWire(ComponentSettings("max.example", "secret"))
        client = FakeClient()
        wire._client = client
        wire._ready = asyncio.Event()
        wire._ready.set()
        element = ET.Element(
            "message",
            {"from": "chat-1@max.example", "to": "group@example", "type": "chat", "id": "1"},
        )
        ET.SubElement(element, "body").text = "https://cdn.example/image.jpg"
        reference = ET.SubElement(
            element,
            "{{{}}}reference".format(XABBER_REFERENCES_NS),
            {"type": "mutable", "begin": "0", "end": "29"},
        )
        ET.SubElement(reference, "{{{}}}file-sharing".format(FILES_NS))

        await wire.send(element)

        self.assertIsNotNone(client.message)
        assert client.message is not None
        self.assertTrue(client.message.sent)
        self.assertEqual([], client.raw)
        self.assertEqual("{jabber:component:accept}message", client.message.xml.tag)
        self.assertEqual("1", client.message.xml.attrib["id"])
        self.assertEqual(
            "https://cdn.example/image.jpg",
            client.message.xml.findtext("{jabber:component:accept}body"),
        )
        self.assertIsNotNone(
            client.message.xml.find("{{{}}}reference".format(XABBER_REFERENCES_NS))
        )

    async def test_keeps_raw_path_for_non_message_stanza(self) -> None:
        wire = SlixmppComponentWire(ComponentSettings("max.example", "secret"))
        client = FakeClient()
        wire._client = client
        wire._ready = asyncio.Event()
        wire._ready.set()

        await wire.send(ET.Element("presence", {"to": "user@example"}))

        self.assertEqual(['<presence to="user@example" />'], client.raw)
        self.assertIsNone(client.message)


if __name__ == "__main__":
    unittest.main()
