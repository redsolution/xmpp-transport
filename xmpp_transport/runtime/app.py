"""Executable CLI for a fault-isolated transport backend process."""

import argparse
import asyncio
import inspect
import os
import signal
import sys
from collections.abc import Iterable, Mapping, Sequence
from importlib import metadata
from pathlib import Path
from typing import Optional

from xmpp_transport.domain.identifiers import BackendId
from xmpp_transport.ports.backend import BackendPlugin

from .composition import SingleBackendRuntime, compose_single_backend
from .config import RuntimeConfig, load_config
from .daemon import DaemonError, daemon_status, daemonize, remove_pid_file, stop_daemon

BACKEND_ENTRY_POINT_GROUP = "xabber_transport.backends"


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="xabber-transport")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--daemon", action="store_true", help="run in the background")
    action.add_argument("--stop", action="store_true", help="stop a daemonized transport")
    action.add_argument("--status", action="store_true", help="show daemon process status")
    parser.add_argument(
        "--config",
        type=Path,
        help="INI path (defaults to XABBER_TRANSPORT_CONFIG or transports.ini)",
    )
    parser.add_argument("--backend", help="select one backend section")
    parser.add_argument(
        "--pid-file",
        help="PID file path for daemon, stop, and status commands",
    )
    parser.add_argument(
        "--daemon-workdir",
        help="working directory after daemonization; defaults to the current directory",
    )
    parser.add_argument(
        "--daemon-umask",
        default="027",
        help="octal umask used after daemonization; defaults to 027",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="validate config and plugin wiring without opening connections",
    )
    return parser.parse_args(argv)


def pid_file_from_args(args: argparse.Namespace, config: RuntimeConfig) -> str:
    backend_name = config.backends[0].name
    value = args.pid_file or f"run/xabber_transport_{backend_name}.pid"
    return os.path.abspath(value)


def parse_umask(value: str) -> int:
    try:
        return int(value, 8)
    except ValueError as exc:
        raise DaemonError(f"Invalid daemon umask {value!r}") from exc


def selected_config(
    args: argparse.Namespace, environment: Optional[Mapping[str, str]] = None
) -> RuntimeConfig:
    source = os.environ if environment is None else environment
    configured_path = source.get("XABBER_TRANSPORT_CONFIG", "transports.ini")
    path = args.config if args.config is not None else Path(configured_path)
    config = load_config(path)
    if args.backend:
        matches = tuple(item for item in config.backends if item.name == args.backend)
        if not matches:
            raise ValueError(f"backend section not found in configuration: {args.backend}")
        return RuntimeConfig(
            backends=matches,
            database=config.database,
            http=config.http,
            credential_key_env=config.credential_key_env,
            environment_file=config.environment_file,
            credential_key_value=config.credential_key_value,
            iq_auth_secret=config.iq_auth_secret,
        )
    if len(config.backends) != 1:
        raise ValueError("select one backend with --backend")
    return config


def discover_backend_plugins() -> Sequence[BackendPlugin]:
    available = metadata.entry_points()
    if hasattr(available, "select"):
        entries = available.select(group=BACKEND_ENTRY_POINT_GROUP)
    else:
        entries = available.get(BACKEND_ENTRY_POINT_GROUP, ())
    external = plugins_from_entry_points(entries)
    from xmpp_transport.adapters.backends.fake import FakeBackendPlugin
    from xmpp_transport.adapters.backends.max import MaxBackendPlugin
    from xmpp_transport.adapters.backends.telegram import TelegramBackendPlugin

    return (FakeBackendPlugin(), MaxBackendPlugin(), TelegramBackendPlugin()) + tuple(external)


def plugins_from_entry_points(entries: Iterable[object]) -> Sequence[BackendPlugin]:
    plugins = []
    seen = set()
    for entry in entries:
        loaded = entry.load()  # type: ignore[attr-defined]
        plugin = loaded() if inspect.isclass(loaded) else loaded
        backend_id = getattr(plugin, "backend_id", None)
        if not isinstance(backend_id, BackendId):
            raise TypeError("backend entry point must expose a BackendPlugin instance")
        if backend_id in seen:
            raise ValueError(f"duplicate backend plugin: {backend_id}")
        seen.add(backend_id)
        plugins.append(plugin)
    return tuple(plugins)


def select_plugin(
    plugins: Sequence[BackendPlugin], backend_name: str
) -> BackendPlugin:
    backend_id = BackendId(backend_name)
    for plugin in plugins:
        if plugin.backend_id == backend_id:
            return plugin
    raise LookupError(
        f"backend plugin is not installed: {backend_name} "
        f"(entry point group: {BACKEND_ENTRY_POINT_GROUP})"
    )


async def serve_runtime(
    runtime: SingleBackendRuntime,
    shutdown_event: Optional[asyncio.Event] = None,
    install_signal_handlers: bool = True,
) -> None:
    stop = shutdown_event if shutdown_event is not None else asyncio.Event()
    loop = asyncio.get_running_loop()
    installed = []
    if install_signal_handlers:
        for signum in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(signum, stop.set)
                installed.append(signum)
            except (NotImplementedError, RuntimeError):
                break
    startup = asyncio.create_task(runtime.start(), name="runtime-startup")
    shutdown = asyncio.create_task(stop.wait(), name="runtime-shutdown-signal")
    try:
        done, _pending = await asyncio.wait(
            (startup, shutdown), return_when=asyncio.FIRST_COMPLETED
        )
        if startup in done:
            await startup
            await shutdown
        else:
            startup.cancel()
            await asyncio.gather(startup, return_exceptions=True)
    finally:
        shutdown.cancel()
        await asyncio.gather(shutdown, return_exceptions=True)
        for signum in installed:
            loop.remove_signal_handler(signum)
        await runtime.close()


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    daemon_started = False
    pid_file = None
    try:
        config = selected_config(args)
        pid_file = pid_file_from_args(args, config)
        if args.status:
            running, pid = daemon_status(pid_file)
            if running:
                print(f"transport {config.backends[0].name} running as pid {pid}")
                return 0
            if pid is None:
                print(f"transport {config.backends[0].name} not running")
            else:
                print(
                    f"transport {config.backends[0].name} not running; "
                    f"stale pid file contains pid {pid}"
                )
            return 1
        if args.stop:
            stop_daemon(pid_file)
            print(f"transport {config.backends[0].name} stopped")
            return 0
        plugins = discover_backend_plugins()
        backend = config.backends[0]
        plugin = select_plugin(plugins, backend.name)
        environment = config.resolved_environment()
        runtime = compose_single_backend(config, plugin, environment)
        if args.check_config:
            print(f"configuration valid for backend: {backend.name}")
            return 0
        if args.daemon:
            daemonize(
                pid_file=pid_file,
                working_directory=args.daemon_workdir,
                umask=parse_umask(args.daemon_umask),
            )
            daemon_started = True
        asyncio.run(serve_runtime(runtime))
        return 0
    except KeyboardInterrupt:
        return 130
    except (DaemonError, LookupError, TypeError, ValueError, ModuleNotFoundError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    finally:
        if daemon_started and pid_file is not None:
            remove_pid_file(pid_file, os.getpid())


if __name__ == "__main__":
    raise SystemExit(main())
