import unittest
from datetime import datetime, timezone
from typing import List

from cryptography.fernet import Fernet

from xmpp_transport.adapters.events import InMemoryEventBus
from xmpp_transport.domain.events import BackendEvent, EventEnvelope, SessionState, SessionStateChanged
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
            iq_auth_secret="shared-roster-iq-secret-at-least-32-bytes",
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
            iq_auth_secret="shared-roster-iq-secret-at-least-32-bytes",
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
            iq_auth_secret="shared-roster-iq-secret-at-least-32-bytes",
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

    def test_requires_iq_auth_secret(self) -> None:
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

        with self.assertRaisesRegex(ValueError, "iq_auth_secret"):
            compose_single_backend(
                config,
                FakePlugin(),  # type: ignore[arg-type]
                {
                    "FAKE_COMPONENT_PASSWORD": "component-secret",
                    "CREDENTIAL_KEY": key,
                },
            )


if __name__ == "__main__":
    unittest.main()
