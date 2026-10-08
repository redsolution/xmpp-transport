"""Python 3.9-compatible ownership and shutdown for background tasks."""

import asyncio
from dataclasses import dataclass
from typing import Awaitable, List, Optional, Protocol, Sequence, Tuple

from .health import HealthState


class TaskSupervisor:
    def __init__(self) -> None:
        self._tasks: List[asyncio.Task[None]] = []
        self._closed = False

    def create_task(self, operation: Awaitable[None], name: Optional[str] = None) -> None:
        if self._closed:
            raise RuntimeError("task supervisor is closed")
        self._tasks.append(asyncio.create_task(operation, name=name))

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

    async def __aenter__(self) -> "TaskSupervisor":
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        await self.close()


class StartableResource(Protocol):
    async def start(self) -> object:
        ...

    async def close(self) -> None:
        ...


class RestorableResource(Protocol):
    async def restore(self) -> None:
        ...

    async def close(self) -> None:
        ...


class ClosableResource(Protocol):
    async def close(self) -> None:
        ...


@dataclass(frozen=True)
class ShutdownFailure:
    resource: str
    exception_type: str


class RuntimeShutdownError(Exception):
    def __init__(self, failures: Tuple[ShutdownFailure, ...]) -> None:
        self.failures = failures
        super().__init__("{} runtime resource(s) failed to close".format(len(failures)))


class ApplicationRuntime:
    """Starts dependencies in order and always tears them down in reverse order."""

    def __init__(
        self,
        health: HealthState,
        health_server: StartableResource,
        database: StartableResource,
        sessions: RestorableResource,
        event_bus: ClosableResource,
        gateways: Sequence[StartableResource] = (),
        background_resources: Sequence[StartableResource] = (),
        managed_resources: Sequence[ClosableResource] = (),
    ) -> None:
        self._health = health
        self._health_server = health_server
        self._database = database
        self._sessions = sessions
        self._event_bus = event_bus
        self._gateways = tuple(gateways)
        self._background_resources = tuple(background_resources)
        self._managed_resources = tuple(managed_resources)
        self._started = False
        self._closed = False

    async def start(self) -> None:
        if self._closed:
            raise RuntimeError("application runtime is closed")
        if self._started:
            return
        self._started = True
        try:
            await self._health_server.start()
            await self._database.start()
            for resource in self._background_resources:
                await resource.start()
            for gateway in self._gateways:
                await gateway.start()
            await self._sessions.restore()
        except BaseException:
            self._health.mark_failed()
            raise
        self._health.mark_ready()

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._health.mark_stopping()
        failures = []
        for name, resource in (
            *(("managed_resource", resource) for resource in reversed(self._managed_resources)),
            *(
                ("background_resource", resource)
                for resource in reversed(self._background_resources)
            ),
            ("sessions", self._sessions),
            ("event_bus", self._event_bus),
            *(("gateway", gateway) for gateway in reversed(self._gateways)),
            ("database", self._database),
            ("health_server", self._health_server),
        ):
            try:
                await resource.close()
            except Exception as exc:
                failures.append(ShutdownFailure(name, type(exc).__name__))
        if failures:
            raise RuntimeShutdownError(tuple(failures))

    async def __aenter__(self) -> "ApplicationRuntime":
        await self.start()
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        await self.close()
