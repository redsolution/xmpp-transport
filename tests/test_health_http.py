import tempfile
import unittest
from typing import Any, Dict, List, Tuple

from xmpp_transport.adapters.web.health import AiohttpHealthServer
from xmpp_transport.runtime.health import HealthState


class FakeRouter:
    def __init__(self) -> None:
        self.routes: List[Tuple[str, object]] = []

    def add_get(self, path: str, handler: object) -> None:
        self.routes.append((path, handler))

    def add_static(self, path: str, directory: object, **kwargs: object) -> None:
        self.routes.append((path, directory))


class FakeApplication:
    def __init__(self) -> None:
        self.router = FakeRouter()


class FakeRunner:
    def __init__(self, application: FakeApplication) -> None:
        self.application = application
        self.setup_count = 0
        self.cleanup_count = 0

    async def setup(self) -> None:
        self.setup_count += 1

    async def cleanup(self) -> None:
        self.cleanup_count += 1


class FakeSite:
    def __init__(self, runner: FakeRunner, host: str, port: int) -> None:
        self.runner = runner
        self.host = host
        self.port = port
        self.started = 0

    async def start(self) -> None:
        self.started += 1


class FakeWeb:
    def __init__(self) -> None:
        self.application: FakeApplication = None  # type: ignore[assignment]
        self.runner: FakeRunner = None  # type: ignore[assignment]
        self.site: FakeSite = None  # type: ignore[assignment]

    def Application(self) -> FakeApplication:
        self.application = FakeApplication()
        return self.application

    def AppRunner(self, application: FakeApplication) -> FakeRunner:
        self.runner = FakeRunner(application)
        return self.runner

    def TCPSite(self, runner: FakeRunner, host: str, port: int) -> FakeSite:
        self.site = FakeSite(runner, host, port)
        return self.site

    @staticmethod
    def json_response(payload: Dict[str, Any], status: int) -> Dict[str, Any]:
        return {"payload": payload, "status": status}


class HealthHttpTests(unittest.IsolatedAsyncioTestCase):
    async def test_registers_endpoints_and_closes_runner(self) -> None:
        web = FakeWeb()
        server = AiohttpHealthServer(HealthState(), "127.0.0.1", 8080, web)
        await server.start()
        await server.start()
        self.assertEqual(["/live", "/ready"], [path for path, _ in web.application.router.routes])
        self.assertEqual(1, web.runner.setup_count)
        self.assertEqual(1, web.site.started)
        await server.close()
        await server.close()
        self.assertEqual(1, web.runner.cleanup_count)

    async def test_registers_optional_media_proxy(self) -> None:
        web = FakeWeb()

        async def media_handler(request):  # type: ignore[no-untyped-def]
            return request

        server = AiohttpHealthServer(
            HealthState(), "127.0.0.1", 8080, web, media_handler=media_handler
        )
        await server.start()

        self.assertEqual(
            ["/media/{token}/{filename}", "/live", "/ready"],
            [path for path, _ in web.application.router.routes],
        )
        await server.close()

    async def test_registers_optional_avatar_cache(self) -> None:
        web = FakeWeb()

        async def avatar_handler(request):  # type: ignore[no-untyped-def]
            return request

        server = AiohttpHealthServer(
            HealthState(), "127.0.0.1", 8080, web, avatar_handler=avatar_handler
        )
        await server.start()

        self.assertEqual(
            ["/avatar/{filename}", "/live", "/ready"],
            [path for path, _ in web.application.router.routes],
        )
        await server.close()

    async def test_registers_login_qr_directory(self) -> None:
        web = FakeWeb()
        with tempfile.TemporaryDirectory() as directory:
            server = AiohttpHealthServer(
                HealthState(),
                "127.0.0.1",
                8080,
                web,
                qr_storage_dir=directory,
            )
            await server.start()
            self.assertEqual(
                ["/qr/", "/live", "/ready"],
                [path for path, _ in web.application.router.routes],
            )
            await server.close()

    async def test_readiness_changes_response_status(self) -> None:
        health = HealthState()
        web = FakeWeb()
        server = AiohttpHealthServer(health, "127.0.0.1", 8080, web)
        await server.start()
        unavailable = await server._ready(object())
        self.assertEqual(503, unavailable["status"])
        health.mark_ready()
        ready = await server._ready(object())
        self.assertEqual(200, ready["status"])
        await server.close()

    async def test_failed_runtime_is_not_live(self) -> None:
        health = HealthState()
        health.mark_failed()
        web = FakeWeb()
        server = AiohttpHealthServer(health, "127.0.0.1", 8080, web)
        await server.start()
        response = await server._live(object())
        self.assertEqual(503, response["status"])
        await server.close()


if __name__ == "__main__":
    unittest.main()
