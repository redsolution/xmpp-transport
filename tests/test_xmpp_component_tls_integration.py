"""Local socket tests for the component's direct TLS connection."""

import asyncio
import datetime
import hashlib
import socket
import ssl
import tempfile
import unittest
from pathlib import Path
from xml.etree import ElementTree as ET

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from xmpp_transport.adapters.xmpp.component import ComponentSettings, SlixmppComponentWire


COMPONENT_NS = "jabber:component:accept"
ROSTER_NS = "jabber:iq:roster"
SERVER_NAME = "xmpp.test.local"
SECRET = "test-secret"


def make_certificates(directory: Path, leaf_name: str):
    now = datetime.datetime.utcnow()
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test component CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, leaf_name)]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(leaf_name)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = directory / "ca.pem"
    cert_path = directory / "server.pem"
    key_path = directory / "server.key"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_path, cert_path, key_path


class ComponentTlsSocketTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        # Some CI sandboxes prohibit even loopback sockets. Run these tests
        # wherever local TCP is available, and keep the rest of the suite usable.
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", 0))
        except PermissionError:
            self.skipTest("local TCP sockets are not permitted")
        self.tempdir = tempfile.TemporaryDirectory()
        self.directory = Path(self.tempdir.name)
        self.servers = []
        self.connections = set()
        self.wires = []
        self.allow_tls_resets = False
        loop = asyncio.get_running_loop()
        self.previous_exception_handler = loop.get_exception_handler()

        def on_loop_error(event_loop, context):  # type: ignore[no-untyped-def]
            if self.allow_tls_resets and isinstance(
                context.get("exception"), ConnectionResetError
            ):
                return
            if self.previous_exception_handler is not None:
                self.previous_exception_handler(event_loop, context)
            else:
                event_loop.default_exception_handler(context)

        loop.set_exception_handler(on_loop_error)

    async def asyncTearDown(self) -> None:
        for wire in self.wires:
            await wire.close()
        for server in self.servers:
            server.close()
            await server.wait_closed()
        if self.connections:
            await asyncio.gather(*self.connections, return_exceptions=True)
        asyncio.get_running_loop().set_exception_handler(self.previous_exception_handler)
        self.tempdir.cleanup()

    async def listen(self, handler, ssl_context=None):  # type: ignore[no-untyped-def]
        async def tracked(reader, writer):  # type: ignore[no-untyped-def]
            task = asyncio.current_task()
            self.connections.add(task)
            try:
                await handler(reader, writer)
            finally:
                writer.close()
                await writer.wait_closed()
                self.connections.discard(task)

        server = await asyncio.start_server(
            tracked, "127.0.0.1", 0, ssl=ssl_context,
        )
        self.servers.append(server)
        return server.sockets[0].getsockname()[1]

    def wire(self, port: int, ca_path: Path, *, server_name=SERVER_NAME):
        settings = ComponentSettings(
            "max.example", SECRET, host="127.0.0.1", port=port,
            tls=True, tls_server_name=server_name, tls_ca_file=str(ca_path),
            connect_timeout=0.2, reconnect_delay=0.05,
        )
        wire = SlixmppComponentWire(settings)

        async def on_message(_stanza):  # type: ignore[no-untyped-def]
            pass

        wire.set_message_handler(on_message)
        self.wires.append(wire)
        return wire

    @staticmethod
    async def read_open_stream(reader):  # type: ignore[no-untyped-def]
        while True:
            chunk = await reader.readuntil(b">")
            if b"<stream:stream" in chunk:
                return chunk

    @staticmethod
    async def serve_component(reader, writer, seen, *, close_after_handshake=False):  # type: ignore[no-untyped-def]
        seen.append("tls")
        await ComponentTlsSocketTests.read_open_stream(reader)
        seen.append("stream")
        writer.write(
            b"<stream:stream xmlns='jabber:component:accept' "
            b"xmlns:stream='http://etherx.jabber.org/streams' id='test-stream'>"
        )
        await writer.drain()
        handshake = await reader.readuntil(b"</handshake>")
        digest = hashlib.sha1(b"test-stream" + SECRET.encode()).hexdigest().encode()
        assert digest in handshake
        seen.append("handshake")
        writer.write(b"<handshake/>")
        await writer.drain()
        if close_after_handshake:
            writer.write(b"</stream:stream>")
            await writer.drain()
            await asyncio.wait_for(reader.read(), timeout=1)
            return
        iq_bytes = await reader.readuntil(b"</iq>")
        iq = ET.fromstring(
            b"<root xmlns='jabber:component:accept'>" + iq_bytes + b"</root>"
        )[0]
        assert iq.tag == "{%s}iq" % COMPONENT_NS
        assert iq.attrib["type"] == "set"
        assert iq.find("{%s}query" % ROSTER_NS) is not None
        seen.append("iq")
        reply = (
            "<iq xmlns='%s' type='result' id='%s' from='example.test' "
            "to='max.example'><query xmlns='%s'/></iq>"
        ) % (COMPONENT_NS, iq.attrib["id"], ROSTER_NS)
        writer.write(reply.encode())
        await writer.drain()
        await reader.read()

    async def test_valid_tls_authenticates_and_sends_roster_iq(self) -> None:
        ca_path, cert_path, key_path = make_certificates(self.directory, SERVER_NAME)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert_path, key_path)
        seen = []

        async def handler(reader, writer):  # type: ignore[no-untyped-def]
            await self.serve_component(reader, writer, seen)

        port = await self.listen(handler, server_context)
        wire = self.wire(port, ca_path)
        await asyncio.wait_for(wire.start(), timeout=2)
        iq = ET.Element("iq", {"to": "example.test", "from": "max.example"})
        ET.SubElement(iq, "{%s}query" % ROSTER_NS)
        response = await asyncio.wait_for(wire.request(iq, timeout=1), timeout=2)

        self.assertEqual("result", response.attrib["type"])
        self.assertEqual(["tls", "stream", "handshake", "iq"], seen)

    async def test_reconnect_authenticates_again_over_tls(self) -> None:
        ca_path, cert_path, key_path = make_certificates(self.directory, SERVER_NAME)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert_path, key_path)
        seen = []
        sessions = []

        async def handler(reader, writer):  # type: ignore[no-untyped-def]
            sessions.append(1)
            await self.serve_component(
                reader, writer, seen, close_after_handshake=len(sessions) == 1,
            )

        port = await self.listen(handler, server_context)
        wire = self.wire(port, ca_path)
        await asyncio.wait_for(wire.start(), timeout=2)

        async def wait_for_second_session() -> None:
            while len(sessions) < 2 or not wire._ready.is_set():
                await asyncio.sleep(0.01)

        await asyncio.wait_for(wait_for_second_session(), timeout=2)
        iq = ET.Element("iq", {"to": "example.test", "from": "max.example"})
        ET.SubElement(iq, "{%s}query" % ROSTER_NS)
        response = await asyncio.wait_for(wire.request(iq, timeout=1), timeout=2)

        self.assertEqual("result", response.attrib["type"])
        self.assertEqual(
            ["tls", "stream", "handshake", "tls", "stream", "handshake", "iq"],
            seen,
        )

    async def test_wrong_certificate_name_never_opens_xml_stream(self) -> None:
        self.allow_tls_resets = True
        ca_path, cert_path, key_path = make_certificates(self.directory, "wrong.test.local")
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert_path, key_path)
        seen = []
        async def handler(reader, writer):  # type: ignore[no-untyped-def]
            seen.append("stream")

        port = await self.listen(handler, server_context)
        wire = self.wire(port, ca_path)

        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(wire.start(), timeout=0.4)
        self.assertEqual([], seen)
        self.assertFalse(wire._ready.is_set())
        with self.assertRaises(ConnectionError):
            await wire.request(ET.Element("iq"))

    async def test_untrusted_certificate_never_opens_xml_stream(self) -> None:
        self.allow_tls_resets = True
        _, cert_path, key_path = make_certificates(self.directory, SERVER_NAME)
        other_dir = self.directory / "other"
        other_dir.mkdir()
        other_ca_path, _, _ = make_certificates(other_dir, SERVER_NAME)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert_path, key_path)
        seen = []
        async def handler(reader, writer):  # type: ignore[no-untyped-def]
            seen.append("stream")

        port = await self.listen(handler, server_context)
        wire = self.wire(port, other_ca_path)

        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(wire.start(), timeout=0.4)
        self.assertEqual([], seen)
        self.assertFalse(wire._ready.is_set())
        with self.assertRaises(ConnectionError):
            await wire.request(ET.Element("iq"))

    async def test_plaintext_listener_receives_only_tls_client_hello(self) -> None:
        ca_path, _, _ = make_certificates(self.directory, SERVER_NAME)
        received = []

        async def handler(reader, writer):  # type: ignore[no-untyped-def]
            received.append(await asyncio.wait_for(reader.read(4096), timeout=1))

        port = await self.listen(handler)
        wire = self.wire(port, ca_path)
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(wire.start(), timeout=0.4)

        self.assertTrue(received)
        self.assertTrue(all(data.startswith(b"\x16\x03") for data in received))
        self.assertTrue(all(b"<stream" not in data for data in received))
        self.assertTrue(all(b"<handshake" not in data for data in received))
        self.assertTrue(all(b"<iq" not in data for data in received))
        self.assertFalse(wire._ready.is_set())
        with self.assertRaises(ConnectionError):
            await wire.request(ET.Element("iq"))


if __name__ == "__main__":
    unittest.main()
