import asyncio
import tempfile
import unittest
from pathlib import Path

from xmpp_transport.domain.identifiers import BackendId
from xmpp_transport.runtime.app import (
    discover_backend_plugins,
    parse_args,
    parse_umask,
    pid_file_from_args,
    plugins_from_entry_points,
    select_plugin,
    selected_config,
    serve_runtime,
)


class FakePlugin:
    backend_id = BackendId("fake")


class FakeEntryPoint:
    def __init__(self, value):  # type: ignore[no-untyped-def]
        self.value = value

    def load(self):  # type: ignore[no-untyped-def]
        return self.value


class CliConfigurationTests(unittest.TestCase):
    def test_parses_daemon_lifecycle_options(self) -> None:
        args = parse_args(
            [
                "--backend",
                "telegram",
                "--daemon",
                "--pid-file",
                "/run/xabber-transport/telegram.pid",
                "--daemon-workdir",
                "/opt/xmpp-transport",
            ]
        )
        self.assertTrue(args.daemon)
        self.assertEqual("/run/xabber-transport/telegram.pid", args.pid_file)
        self.assertEqual("/opt/xmpp-transport", args.daemon_workdir)

    def test_daemon_actions_are_mutually_exclusive(self) -> None:
        with self.assertRaises(SystemExit):
            parse_args(["--daemon", "--stop"])

    def test_backend_specific_default_pid_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "transports.ini"
            path.write_text(
                "[backend:max]\ncomponent_jid=max.example.com\n",
                encoding="utf-8",
            )
            args = parse_args(["--config", str(path), "--backend", "max"])
            config = selected_config(args, {})
        self.assertTrue(pid_file_from_args(args, config).endswith("xabber_transport_max.pid"))

    def test_parses_octal_daemon_umask(self) -> None:
        self.assertEqual(0o027, parse_umask("027"))

    def test_selects_backend_from_multi_backend_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "transports.ini"
            path.write_text(
                "[backend:telegram]\ncomponent_jid=telegram.example.com\n"
                "[backend:max]\ncomponent_jid=max.example.com\n"
                "[database]\ndsn=postgresql://db/transport\n"
                "[security]\n"
                "iq_auth_secret=shared-roster-iq-secret-at-least-32-bytes\n",
                encoding="utf-8",
            )
            args = parse_args(["--config", str(path), "--backend", "max"])
            config = selected_config(args, {})
        self.assertEqual(["max"], [item.name for item in config.backends])
        self.assertEqual(
            "shared-roster-iq-secret-at-least-32-bytes",
            config.iq_auth_secret,
        )

    def test_uses_configuration_path_from_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "custom.ini"
            path.write_text(
                "[backend:fake]\ncomponent_jid=fake.example.com\n",
                encoding="utf-8",
            )
            args = parse_args([])
            config = selected_config(args, {"XABBER_TRANSPORT_CONFIG": str(path)})
        self.assertEqual("fake", config.backends[0].name)

    def test_requires_backend_selection_for_multiple_sections(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "transports.ini"
            path.write_text(
                "[backend:one]\ncomponent_jid=one.example.com\n"
                "[backend:two]\ncomponent_jid=two.example.com\n",
                encoding="utf-8",
            )
            args = parse_args(["--config", str(path)])
            with self.assertRaisesRegex(ValueError, "select one backend"):
                selected_config(args, {})


class PluginDiscoveryTests(unittest.TestCase):
    def test_builtin_fake_backend_is_discoverable(self) -> None:
        plugins = discover_backend_plugins()
        self.assertIn(BackendId("fake"), [plugin.backend_id for plugin in plugins])

    def test_builtin_max_backend_is_discoverable(self) -> None:
        plugins = discover_backend_plugins()
        self.assertIn(BackendId("max"), [plugin.backend_id for plugin in plugins])

    def test_loads_plugin_instance_and_class(self) -> None:
        class OtherPlugin:
            backend_id = BackendId("other")

        plugins = plugins_from_entry_points(
            (FakeEntryPoint(FakePlugin()), FakeEntryPoint(OtherPlugin))
        )
        self.assertEqual(
            [BackendId("fake"), BackendId("other")],
            [plugin.backend_id for plugin in plugins],
        )

    def test_duplicate_plugin_identity_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            plugins_from_entry_points(
                (FakeEntryPoint(FakePlugin()), FakeEntryPoint(FakePlugin()))
            )

    def test_select_plugin_reports_missing_backend(self) -> None:
        with self.assertRaises(LookupError) as context:
            select_plugin((FakePlugin(),), "telegram")  # type: ignore[arg-type]
        self.assertIn("xabber_transport.backends", str(context.exception))


class FakeRuntime:
    def __init__(self) -> None:
        self.started = 0
        self.closed = 0

    async def start(self) -> None:
        self.started += 1

    async def close(self) -> None:
        self.closed += 1


class ServeRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_starts_waits_and_always_closes(self) -> None:
        runtime = FakeRuntime()
        shutdown = asyncio.Event()
        shutdown.set()
        await serve_runtime(
            runtime,  # type: ignore[arg-type]
            shutdown_event=shutdown,
            install_signal_handlers=False,
        )
        self.assertEqual((1, 1), (runtime.started, runtime.closed))

    async def test_start_failure_still_closes_runtime(self) -> None:
        class FailingRuntime(FakeRuntime):
            async def start(self) -> None:
                raise ConnectionError("failed")

        runtime = FailingRuntime()
        with self.assertRaises(ConnectionError):
            await serve_runtime(
                runtime,  # type: ignore[arg-type]
                shutdown_event=asyncio.Event(),
                install_signal_handlers=False,
            )
        self.assertEqual(1, runtime.closed)


if __name__ == "__main__":
    unittest.main()
