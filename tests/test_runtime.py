import asyncio
import tempfile
import unittest
from pathlib import Path

from xmpp_transport.domain.identifiers import BackendId
from xmpp_transport.runtime.config import DatabaseConfig, HttpConfig, RuntimeConfig, load_config
from xmpp_transport.runtime.health import HealthState, RuntimeStatus
from xmpp_transport.runtime.lifecycle import ApplicationRuntime, RuntimeShutdownError, TaskSupervisor
from xmpp_transport.runtime.registry import BackendRegistry


class FakePlugin:
    backend_id = BackendId("fake")


class RegistryTests(unittest.TestCase):
    def test_duplicate_backend_is_rejected(self) -> None:
        registry = BackendRegistry([FakePlugin()])  # type: ignore[list-item]
        with self.assertRaises(ValueError):
            registry.register(FakePlugin())  # type: ignore[arg-type]


class ConfigTests(unittest.TestCase):
    def test_reads_multiple_backend_sections(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "transport.ini"
            path.write_text(
                "[backend:telegram]\ncomponent_jid=telegram.example.com\n"
                "[backend:max]\ncomponent_jid=max.example.com\n",
                encoding="utf-8",
            )
            config = load_config(path)
        self.assertEqual(["telegram", "max"], [item.name for item in config.backends])

    def test_reads_database_and_security_without_exposing_dsn(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "transport.ini"
            path.write_text(
                "[backend:telegram]\ncomponent_jid=telegram.example.com\n"
                "[database]\ndsn=postgresql://user:secret@db/transport\n"
                "min_pool_size=2\nmax_pool_size=8\ncommand_timeout=12.5\n"
                "[security]\ncredential_key_env=TEST_CREDENTIAL_KEY\n",
                encoding="utf-8",
            )
            config = load_config(path)
        self.assertIsNotNone(config.database)
        assert config.database is not None
        self.assertEqual(2, config.database.min_pool_size)
        self.assertEqual("TEST_CREDENTIAL_KEY", config.credential_key_env)
        self.assertNotIn("secret", repr(config))

    def test_reads_inline_secrets_without_exposing_them_in_repr(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "transport.ini"
            path.write_text(
                "[backend:max]\ncomponent_jid=max.example.com\n"
                "component_password=private-component-secret\n"
                "[database]\ndsn=postgresql://user:private@db/transport\n"
                "[security]\ncredential_key=private-fernet-key\n"
                "iq_auth_secret=private-shared-iq-secret-at-least-32-bytes\n",
                encoding="utf-8",
            )
            config = load_config(path)

        self.assertEqual("private-component-secret", config.backends[0].component_password)
        self.assertEqual(b"private-fernet-key", config.credential_key({}))
        self.assertEqual(
            "private-shared-iq-secret-at-least-32-bytes",
            config.iq_auth_secret,
        )
        representation = repr(config)
        self.assertNotIn("private-component-secret", representation)
        self.assertNotIn("private-fernet-key", representation)
        self.assertNotIn("private-shared-iq-secret", representation)
        self.assertNotIn("postgresql://user:private", representation)

    def test_credential_key_is_loaded_from_named_environment_variable(self) -> None:
        config = RuntimeConfig((), credential_key_env="CUSTOM_KEY")
        self.assertEqual(b"safe-key", config.credential_key({"CUSTOM_KEY": "safe-key"}))

    def test_missing_credential_key_is_reported_without_value(self) -> None:
        config = RuntimeConfig((), credential_key_env="CUSTOM_KEY")
        with self.assertRaises(ValueError) as context:
            config.credential_key({})
        self.assertIn("CUSTOM_KEY", str(context.exception))

    def test_non_ascii_credential_key_is_rejected_without_disclosure(self) -> None:
        config = RuntimeConfig((), credential_key_env="CUSTOM_KEY")
        secret = "секрет"
        with self.assertRaises(ValueError) as context:
            config.credential_key({"CUSTOM_KEY": secret})
        self.assertNotIn(secret, str(context.exception))
        self.assertIsNone(context.exception.__cause__)

    def test_database_pool_sizes_are_validated(self) -> None:
        with self.assertRaises(ValueError):
            DatabaseConfig("postgresql://db/transport", min_pool_size=3, max_pool_size=2)

    def test_database_dsn_can_be_resolved_from_environment(self) -> None:
        unresolved = DatabaseConfig("", dsn_env="DATABASE_URL", schema="transport")
        resolved = unresolved.resolve({"DATABASE_URL": "postgresql://private"})
        self.assertEqual("postgresql://private", resolved.dsn)
        self.assertEqual("transport", resolved.schema)
        self.assertNotIn("private", repr(resolved))

    def test_database_dsn_environment_is_required(self) -> None:
        unresolved = DatabaseConfig("", dsn_env="DATABASE_URL")
        with self.assertRaisesRegex(ValueError, "DATABASE_URL"):
            unresolved.resolve({})

    def test_reads_http_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "transport.ini"
            path.write_text(
                "[backend:fake]\ncomponent_jid=fake.example.com\n"
                "[http]\nhost=0.0.0.0\nport=9090\n",
                encoding="utf-8",
            )
            config = load_config(path)
        self.assertEqual(HttpConfig("0.0.0.0", 9090), config.http)

    def test_http_port_is_validated(self) -> None:
        with self.assertRaises(ValueError):
            HttpConfig(port=0)

    def test_dotenv_is_parsed_as_data_and_process_environment_wins(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dotenv = root / ".env"
            dotenv.write_text(
                "DATABASE_URL=postgresql://from-file\n"
                "CRON=0 3 * * *\n"
                "QUOTED='value with spaces'\n",
                encoding="utf-8",
            )
            config_path = root / "transport.ini"
            config_path.write_text(
                "[environment]\nfile=.env\n"
                "[backend:fake]\ncomponent_jid=fake.example.com\n",
                encoding="utf-8",
            )
            config = load_config(config_path)
            environment = config.resolved_environment(
                {"DATABASE_URL": "postgresql://override"}
            )
        self.assertEqual("postgresql://override", environment["DATABASE_URL"])
        self.assertEqual("0 3 * * *", environment["CRON"])
        self.assertEqual("value with spaces", environment["QUOTED"])


class SupervisorTests(unittest.IsolatedAsyncioTestCase):
    async def test_close_cancels_owned_tasks(self) -> None:
        cancelled = asyncio.Event()

        async def worker() -> None:
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        supervisor = TaskSupervisor()
        supervisor.create_task(worker(), name="test-worker")
        await asyncio.sleep(0)
        await supervisor.close()
        self.assertTrue(cancelled.is_set())


class OrderedResource:
    def __init__(self, name: str, calls: list, fail_close: bool = False) -> None:
        self.name = name
        self.calls = calls
        self.fail_close = fail_close

    async def start(self) -> object:
        self.calls.append("start:" + self.name)
        return self

    async def restore(self) -> None:
        self.calls.append("restore:" + self.name)

    async def close(self) -> None:
        self.calls.append("close:" + self.name)
        if self.fail_close:
            raise RuntimeError("private failure")


class ApplicationRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_start_and_close_order_and_health_transitions(self) -> None:
        calls = []
        health = HealthState()
        server = OrderedResource("health", calls)
        database = OrderedResource("database", calls)
        sessions = OrderedResource("sessions", calls)
        events = OrderedResource("events", calls)
        authentication = OrderedResource("authentication", calls)
        qr_cleanup = OrderedResource("qr_cleanup", calls)
        runtime = ApplicationRuntime(
            health,
            server,
            database,
            sessions,
            events,
            background_resources=(qr_cleanup,),
            managed_resources=(authentication,),
        )

        self.assertEqual(RuntimeStatus.STARTING, health.snapshot().status)
        await runtime.start()
        self.assertTrue(health.snapshot().ready)
        await runtime.close()
        self.assertEqual(RuntimeStatus.STOPPING, health.snapshot().status)
        self.assertEqual(
            [
                "start:health",
                "start:database",
                "start:qr_cleanup",
                "restore:sessions",
                "close:authentication",
                "close:qr_cleanup",
                "close:sessions",
                "close:events",
                "close:database",
                "close:health",
            ],
            calls,
        )

    async def test_close_continues_after_resource_failure(self) -> None:
        calls = []
        health = HealthState()
        runtime = ApplicationRuntime(
            health,
            OrderedResource("health", calls),
            OrderedResource("database", calls),
            OrderedResource("sessions", calls, fail_close=True),
            OrderedResource("events", calls),
        )
        await runtime.start()
        with self.assertRaises(RuntimeShutdownError) as context:
            await runtime.close()
        self.assertIn("close:health", calls)
        self.assertEqual("RuntimeError", context.exception.failures[0].exception_type)
        self.assertNotIn("private failure", str(context.exception))


if __name__ == "__main__":
    unittest.main()
