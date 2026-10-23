import unittest
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from cryptography.fernet import Fernet

from xmpp_transport.adapters.events import InMemoryEventBus
from xmpp_transport.domain.events import (
    BackendEvent,
    EventEnvelope,
    SessionState,
    SessionStateChanged,
)
from xmpp_transport.domain.identifiers import BackendId, BindingId, EventId
from xmpp_transport.runtime.composition import EventSinkRelay, compose_single_backend
from xmpp_transport.runtime.config import (
    BackendConfig,
    DatabaseConfig,
    HttpConfig,
    RuntimeConfig,
)


class RecordingHandler:
    def __init__(self) -> None:
        self.events: List[BackendEvent] = []

    async def handle(self, event: BackendEvent) -> None:
        self.events.append(event)


class FakePlugin:
    backend_id = BackendId("fake")

    def create_authentication(self, binding_id):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def create_session(self, binding_id, credentials, event_sink):  # type: ignore[no-untyped-def]
        raise NotImplementedError


class EventSinkRelayTests(unittest.IsolatedAsyncioTestCase):
    async def test_requires_one_binding_then_delegates(self) -> None:
        relay = EventSinkRelay()
        event = SessionStateChanged(
            EventEnvelope(
                event_id=EventId("event-1"),
                event_type=SessionStateChanged.EVENT_TYPE,
                schema_version=1,
                backend_id=BackendId("fake"),
                binding_id=BindingId("binding-1"),
                occurred_at=datetime.now(timezone.utc),
            ),
            SessionState.CONNECTED,
        )
        with self.assertRaises(RuntimeError):
            await relay.publish(event)
        handler = RecordingHandler()
        bus = InMemoryEventBus(handler)
        relay.bind(bus)
        with self.assertRaises(RuntimeError):
            relay.bind(bus)
        await relay.publish(event)
        await bus.close()
        self.assertEqual([event], handler.events)


class CompositionTests(unittest.TestCase):
    def test_component_tls_settings_are_wired_and_validated(self) -> None:
        key = Fernet.generate_key().decode("ascii")
        environment = {"FAKE_COMPONENT_PASSWORD": "secret", "CREDENTIAL_KEY": key}

        def compose(options):  # type: ignore[no-untyped-def]
            config = RuntimeConfig(
                backends=(BackendConfig("fake", "fake.example.com", options),),
                database=DatabaseConfig("postgresql://user:private@db/transport"),
                credential_key_env="CREDENTIAL_KEY",
            )
            return compose_single_backend(config, FakePlugin(), environment)  # type: ignore[arg-type]

        base = {"component_password_env": "FAKE_COMPONENT_PASSWORD"}
        self.assertFalse(compose(base)._wire._settings.tls)
        with tempfile.TemporaryDirectory() as directory:
            ca_file = Path(directory) / "ca.pem"
            ca_file.write_text("test CA placeholder", encoding="ascii")
            options = dict(base, component_tls="true", component_tls_server_name="xmpp.example.com",
                           component_tls_ca_file=str(ca_file), server_ip="127.0.0.1")
            settings = compose(options)._wire._settings
            self.assertTrue(settings.tls)
            self.assertEqual("127.0.0.1", settings.host)
            self.assertEqual("xmpp.example.com", settings.tls_server_name)
            self.assertEqual(str(ca_file), settings.tls_ca_file)

        for overrides, error in (
            ({"component_tls": "maybe"}, "component_tls"),
            ({"component_tls": "true"}, "tls_server_name"),
            ({"component_tls": "true", "component_tls_server_name": " "}, "tls_server_name"),
            ({"component_tls": "false", "component_tls_server_name": "xmpp.example.com"},
             "TLS options require TLS"),
            ({"component_tls": "true", "component_tls_server_name": "xmpp.example.com",
              "component_tls_ca_file": ""}, "tls_ca_file"),
            ({"component_tls": "true", "component_tls_server_name": "xmpp.example.com",
              "component_tls_ca_file": "/missing/ca.pem"}, "tls_ca_file"),
        ):
            with self.subTest(overrides=overrides), self.assertRaisesRegex(ValueError, error):
                compose(dict(base, **overrides))

    def test_builds_single_backend_without_importing_optional_runtime_drivers(self) -> None:
        key = Fernet.generate_key().decode("ascii")
        config = RuntimeConfig(
            backends=(
                BackendConfig(
                    "fake",
                    "fake.example.com",
                    {
                        "component_password_env": "FAKE_COMPONENT_PASSWORD",
                    },
                ),
            ),
            database=DatabaseConfig("postgresql://user:private@db/transport"),
            credential_key_env="CREDENTIAL_KEY",
        )
        runtime = compose_single_backend(
            config,
            FakePlugin(),  # type: ignore[arg-type]
            {
                "FAKE_COMPONENT_PASSWORD": "component-secret",
                "CREDENTIAL_KEY": key,
            },
        )
        self.assertEqual("starting", runtime.health.snapshot().status.value)
        with self.assertRaisesRegex(RuntimeError, "not initialized"):
            _ = runtime.authentication

    def test_requires_database_and_component_password(self) -> None:
        key = Fernet.generate_key().decode("ascii")
        without_database = RuntimeConfig(
            (BackendConfig("fake", "fake.example.com", {}),),
            credential_key_env="CREDENTIAL_KEY",
        )
        with self.assertRaises(ValueError):
            compose_single_backend(
                without_database,
                FakePlugin(),  # type: ignore[arg-type]
                {"CREDENTIAL_KEY": key},
            )

    def test_backend_http_endpoint_overrides_shared_fallback(self) -> None:
        key = Fernet.generate_key().decode("ascii")
        config = RuntimeConfig(
            backends=(
                BackendConfig(
                    "fake",
                    "fake.example.com",
                    {
                        "component_password_env": "FAKE_COMPONENT_PASSWORD",
                        "http_host": "127.0.0.2",
                        "http_port": "9081",
                    },
                ),
            ),
            database=DatabaseConfig("postgresql://user:private@db/transport"),
            http=HttpConfig("127.0.0.1", 8080),
            credential_key_env="CREDENTIAL_KEY",
        )

        runtime = compose_single_backend(
            config,
            FakePlugin(),  # type: ignore[arg-type]
            {
                "FAKE_COMPONENT_PASSWORD": "component-secret",
                "CREDENTIAL_KEY": key,
            },
        )

        self.assertEqual("127.0.0.2", runtime._health_server._host)
        self.assertEqual(9081, runtime._health_server._port)

    def test_backend_http_port_is_validated(self) -> None:
        key = Fernet.generate_key().decode("ascii")
        config = RuntimeConfig(
            backends=(
                BackendConfig(
                    "fake",
                    "fake.example.com",
                    {
                        "component_password_env": "FAKE_COMPONENT_PASSWORD",
                        "http_port": "70000",
                    },
                ),
            ),
            database=DatabaseConfig("postgresql://user:private@db/transport"),
            credential_key_env="CREDENTIAL_KEY",
        )

        with self.assertRaisesRegex(ValueError, "http_port"):
            compose_single_backend(
                config,
                FakePlugin(),  # type: ignore[arg-type]
                {
                    "FAKE_COMPONENT_PASSWORD": "component-secret",
                    "CREDENTIAL_KEY": key,
                },
            )

    def test_uses_component_password_for_roster_encryption(self) -> None:
        key = Fernet.generate_key().decode("ascii")
        config = RuntimeConfig(
            backends=(
                BackendConfig(
                    "fake",
                    "fake.example.com",
                    {"component_password_env": "FAKE_COMPONENT_PASSWORD"},
                ),
            ),
            database=DatabaseConfig("postgresql://user:private@db/transport"),
            credential_key_env="CREDENTIAL_KEY",
        )

        runtime = compose_single_backend(
            config,
            FakePlugin(),  # type: ignore[arg-type]
            {"FAKE_COMPONENT_PASSWORD": "component-secret", "CREDENTIAL_KEY": key},
        )
        self.assertEqual("component-secret", runtime._component_password)


if __name__ == "__main__":
    unittest.main()
