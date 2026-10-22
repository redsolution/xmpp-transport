import asyncio
import unittest

from xmpp_transport.application.authentication import AuthenticationCoordinator
from xmpp_transport.domain.auth import AuthChallenge, AuthResponse, AuthState
from xmpp_transport.domain.identifiers import BackendId, BindingId


class Flow:
    def __init__(self) -> None:
        self.closed = 0

    async def start(self) -> AuthChallenge:
        return AuthChallenge(AuthState.WAITING_QR, public_url="https://example.test/qr")

    async def respond(self, response: AuthResponse) -> AuthChallenge:
        return AuthChallenge(AuthState.CONNECTED)

    def credentials(self) -> bytes:
        return b"private"

    async def close(self) -> None:
        self.closed += 1


class ExclusiveFlow(Flow):
    def remote_account_id(self) -> str:
        return "max-account-1"

    def matches_account(self, credentials: bytes) -> bool:
        return credentials == b"private"


class Plugin:
    backend_id = BackendId("max")

    def __init__(self) -> None:
        self.flows = []

    def create_authentication(self, binding_id):  # type: ignore[no-untyped-def]
        flow = Flow()
        self.flows.append(flow)
        return flow


class Registry:
    def __init__(self, plugin: Plugin) -> None:
        self.plugin = plugin

    def get(self, backend_id):  # type: ignore[no-untyped-def]
        return self.plugin


class Bindings:
    def __init__(self) -> None:
        self.saved = []
        self.exclusive_saved = []
        self.displaced = ()

    async def save_encrypted_credentials(self, binding_id, backend_id, credentials):  # type: ignore[no-untyped-def]
        self.saved.append((binding_id, backend_id, credentials))

    async def save_exclusive_credentials(  # type: ignore[no-untyped-def]
        self, binding_id, backend_id, credentials, remote_account_key, matches_legacy
    ):
        assert matches_legacy(b"encrypted:private")
        assert not matches_legacy(b"encrypted:other")
        self.exclusive_saved.append(
            (binding_id, backend_id, credentials, remote_account_key)
        )
        return self.displaced


class Cipher:
    def encrypt(self, value: bytes) -> bytes:
        return b"encrypted:" + value

    def decrypt(self, value: bytes) -> bytes:
        return value.removeprefix(b"encrypted:")

    def remote_account_key(self, backend_id, account_id):  # type: ignore[no-untyped-def]
        return f"{backend_id}:{account_id}".encode("utf-8")


class Sessions:
    def __init__(self) -> None:
        self.started = []
        self.stopped = []

    async def start(self, binding_id, backend_id):  # type: ignore[no-untyped-def]
        self.started.append((binding_id, backend_id))
        return object()

    async def stop(self, binding_id):  # type: ignore[no-untyped-def]
        self.stopped.append(binding_id)


class AuthenticationCoordinatorTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.plugin = Plugin()
        self.bindings = Bindings()
        self.sessions = Sessions()
        self.coordinator = AuthenticationCoordinator(
            Registry(self.plugin),  # type: ignore[arg-type]
            self.bindings,  # type: ignore[arg-type]
            Cipher(),  # type: ignore[arg-type]
            self.sessions,
        )

    async def test_encrypts_persists_and_starts_connected_binding(self) -> None:
        binding_id = BindingId("binding-1")
        backend_id = BackendId("max")
        completed = asyncio.Event()

        async def handle_challenge(_binding_id, _challenge):  # type: ignore[no-untyped-def]
            completed.set()

        self.coordinator._challenge_handler = handle_challenge

        challenge = await self.coordinator.begin(binding_id, backend_id)
        await asyncio.wait_for(completed.wait(), timeout=1)

        self.assertEqual(AuthState.WAITING_QR, challenge.state)
        self.assertEqual(
            [(binding_id, backend_id, b"encrypted:private")], self.bindings.saved
        )
        self.assertEqual([(binding_id, backend_id)], self.sessions.started)
        self.assertEqual([binding_id], self.sessions.stopped)
        self.assertEqual(1, self.plugin.flows[0].closed)

    async def test_restarting_flow_closes_previous_one(self) -> None:
        binding_id = BindingId("binding-1")
        backend_id = BackendId("max")
        await self.coordinator.begin(binding_id, backend_id)
        first = self.plugin.flows[0]

        await self.coordinator.begin(binding_id, backend_id)

        self.assertEqual(1, first.closed)

    async def test_exclusive_login_stops_previous_owner_and_notifies_them(self) -> None:
        binding_id = BindingId("new-owner")
        previous = BindingId("old-owner")
        backend_id = BackendId("max")
        self.bindings.displaced = (previous,)
        notices = []

        async def handle_challenge(owner, challenge):  # type: ignore[no-untyped-def]
            notices.append((owner, challenge))

        self.coordinator._challenge_handler = handle_challenge
        self.plugin.create_authentication = lambda _binding_id: ExclusiveFlow()  # type: ignore[method-assign]

        await self.coordinator.begin(binding_id, backend_id)
        for _attempt in range(20):
            if binding_id not in self.coordinator._tasks:
                break
            await asyncio.sleep(0)

        self.assertEqual([], self.bindings.saved)
        self.assertEqual(
            [(binding_id, backend_id, b"encrypted:private", b"max:max-account-1")],
            self.bindings.exclusive_saved,
        )
        self.assertEqual([previous, binding_id], self.sessions.stopped)
        self.assertEqual([(binding_id, backend_id)], self.sessions.started)
        self.assertEqual(AuthState.EXPIRED, notices[0][1].state)
        self.assertEqual(previous, notices[0][0])
        self.assertIn("другого XMPP-пользователя", notices[0][1].message)

    async def test_notification_failure_does_not_fail_completed_login(self) -> None:
        binding_id = BindingId("binding-1")
        backend_id = BackendId("max")

        async def fail_notification(_binding_id, _challenge):  # type: ignore[no-untyped-def]
            raise LookupError("owner lookup failed")

        self.coordinator._challenge_handler = fail_notification

        with self.assertLogs(
            "xmpp_transport.application.authentication", level="ERROR"
        ) as captured:
            challenge = await self.coordinator.begin(binding_id, backend_id)
            for _attempt in range(20):
                if binding_id not in self.coordinator._tasks:
                    break
                await asyncio.sleep(0)

        self.assertEqual(AuthState.WAITING_QR, challenge.state)
        self.assertEqual(
            [(binding_id, backend_id, b"encrypted:private")], self.bindings.saved
        )
        self.assertEqual([(binding_id, backend_id)], self.sessions.started)
        self.assertNotIn(binding_id, self.coordinator._tasks)
        self.assertTrue(
            any("Authentication notification failed" in line for line in captured.output)
        )

    async def test_close_closes_active_flows(self) -> None:
        await self.coordinator.begin(BindingId("binding-1"), BackendId("max"))
        flow = self.plugin.flows[0]

        await self.coordinator.close()

        self.assertEqual(1, flow.closed)
