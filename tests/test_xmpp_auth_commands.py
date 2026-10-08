import unittest
from types import SimpleNamespace

from xmpp_transport.adapters.xmpp.auth_commands import (
    XmppAuthenticationCommands,
    XmppAuthenticationNotices,
)
from xmpp_transport.adapters.xmpp.message_codec import XmppMessageCodec
from xmpp_transport.domain.auth import AuthChallenge, AuthState
from xmpp_transport.domain.identifiers import BackendId, BindingId
from xmpp_transport.domain.identifiers import RemoteObjectId
from xmpp_transport.domain.models import Contact
from xmpp_transport.ports.backend import ContactSource
from xmpp_transport.ports.repositories import BindingRecord


class Bindings:
    def __init__(self) -> None:
        self.record = BindingRecord(BindingId("binding-1"), BackendId("max"))
        self.lookup = None
        self.ensured = None
        self.disabled = None

    async def ensure_binding(self, bare_jid, backend_id):  # type: ignore[no-untyped-def]
        self.ensured = (bare_jid, backend_id)
        return self.record

    async def binding_for_authentication(self, bare_jid, backend_id):  # type: ignore[no-untyped-def]
        self.lookup = (bare_jid, backend_id)
        return self.record

    async def xmpp_account_for_authentication(self, binding_id):  # type: ignore[no-untyped-def]
        return "user@example.com"

    async def disable_binding(self, binding_id):  # type: ignore[no-untyped-def]
        self.disabled = binding_id


class Authentication:
    def __init__(self) -> None:
        self.begun = None
        self.responses = []
        self.current_state = AuthState.WAITING_PASSWORD

    async def begin(self, binding_id, backend_id):  # type: ignore[no-untyped-def]
        self.begun = (binding_id, backend_id)
        return AuthChallenge(AuthState.WAITING_QR, public_url="https://max.example/qr")

    async def respond(self, binding_id, backend_id, response):  # type: ignore[no-untyped-def]
        self.responses.append((binding_id, backend_id, response))
        return AuthChallenge(AuthState.CONNECTED)

    async def cancel(self, binding_id):  # type: ignore[no-untyped-def]
        return None

    def state(self, binding_id):  # type: ignore[no-untyped-def]
        return self.current_state


class Contacts:
    async def contacts(self):  # type: ignore[no-untyped-def]
        return (Contact(RemoteObjectId("chat-1"), "Alice"),)


class Sessions:
    def __init__(self) -> None:
        self.stopped = None

    async def feature(self, binding_id, feature_type):  # type: ignore[no-untyped-def]
        if feature_type is ContactSource:
            return Contacts()
        return None

    async def stop(self, binding_id):  # type: ignore[no-untyped-def]
        self.stopped = binding_id


class Roster:
    def __init__(self) -> None:
        self.added = None

    async def add_contact(self, binding_id, contact):  # type: ignore[no-untyped-def]
        self.added = (binding_id, contact)


class Wire:
    def __init__(self) -> None:
        self.sent = []

    async def send(self, stanza):  # type: ignore[no-untyped-def]
        self.sent.append(stanza)


class QrStore:
    def create(self, value):  # type: ignore[no-untyped-def]
        self.value = value
        return SimpleNamespace(
            url="https://transport.example/qr/max-login-qr-test.svg",
            name="max-login-qr-test.svg",
            mime_type="image/svg+xml",
            size=123,
        )


class XmppAuthenticationCommandTests(unittest.IsolatedAsyncioTestCase):
    async def test_login_creates_attempt_for_owner_binding(self) -> None:
        bindings = Bindings()
        authentication = Authentication()
        commands = XmppAuthenticationCommands(
            BackendId("max"),
            "max.example.com",
            bindings,  # type: ignore[arg-type]
            authentication,  # type: ignore[arg-type]
            qr_store=QrStore(),  # type: ignore[arg-type]
        )

        response = await commands.handle("user@example.com/device", "/login")

        self.assertTrue(commands.accepts("bot@max.example.com"))
        self.assertTrue(commands.accepts("bot@max.example.com/mobile"))
        self.assertFalse(commands.accepts("max.example.com"))
        self.assertFalse(commands.accepts("chat-1@max.example.com"))
        self.assertEqual(("user@example.com", BackendId("max")), bindings.ensured)
        self.assertEqual(
            (BindingId("binding-1"), BackendId("max")), authentication.begun
        )
        self.assertNotIn("https://max.example/qr", response.body)
        self.assertNotIn("/continue", response.body)
        self.assertIn("сообщит о результате", response.body)
        self.assertEqual("image/svg+xml", response.media[0].mime_type)
        self.assertEqual(
            "https://transport.example/qr/max-login-qr-test.svg",
            response.media[0].uri,
        )

    async def test_status_does_not_start_authentication(self) -> None:
        authentication = Authentication()
        commands = XmppAuthenticationCommands(
            BackendId("max"),
            "max.example.com",
            Bindings(),  # type: ignore[arg-type]
            authentication,  # type: ignore[arg-type]
        )

        response = await commands.handle("user@example.com", "/status")

        self.assertIn("сохранена", response.body)
        self.assertIsNone(authentication.begun)

    async def test_help_lists_original_MAX_commands(self) -> None:
        commands = XmppAuthenticationCommands(
            BackendId("max"),
            "max.example.com",
            Bindings(),  # type: ignore[arg-type]
            Authentication(),  # type: ignore[arg-type]
            supports_phone_contact_addition=True,
        )

        response = await commands.handle("user@example.com", "/help")

        for command in ("/login", "/password", "/status", "/contacts", "/add", "/logout"):
            self.assertIn(command, response.body)
        self.assertIn("/add phone", response.body)
        self.assertEqual("/login", response.buttons[0][0].data)
        self.assertEqual("/help", response.buttons[-1][-1].data)

    async def test_help_hides_phone_add_when_backend_does_not_support_it(self) -> None:
        commands = XmppAuthenticationCommands(
            BackendId("telegram"),
            "telegram.example.com",
            Bindings(),  # type: ignore[arg-type]
            Authentication(),  # type: ignore[arg-type]
            provider_name="TELEGRAM",
        )

        response = await commands.handle("user@example.com", "/help")

        self.assertNotIn("/add phone", response.body)

    async def test_password_command_returns_private_data_form(self) -> None:
        commands = XmppAuthenticationCommands(
            BackendId("max"),
            "max.example.com",
            Bindings(),  # type: ignore[arg-type]
            Authentication(),  # type: ignore[arg-type]
        )

        response = await commands.handle("user@example.com", "/password")

        self.assertEqual(1, len(response.forms))
        self.assertEqual("password", response.forms[0].fields[0].value)
        self.assertEqual("text-private", response.forms[0].fields[1].type)
        self.assertTrue(response.forms[0].fields[1].required)

    async def test_submitted_password_form_uses_authentication_flow(self) -> None:
        authentication = Authentication()
        commands = XmppAuthenticationCommands(
            BackendId("max"),
            "max.example.com",
            Bindings(),  # type: ignore[arg-type]
            authentication,  # type: ignore[arg-type]
        )

        await commands.handle(
            "user@example.com",
            "",
            {"command": "password", "password": "secret"},
        )

        self.assertEqual("secret", authentication.responses[0][2].secret)

    async def test_contacts_uses_active_backend_feature(self) -> None:
        commands = XmppAuthenticationCommands(
            BackendId("max"),
            "max.example.com",
            Bindings(),  # type: ignore[arg-type]
            Authentication(),  # type: ignore[arg-type]
            sessions=Sessions(),  # type: ignore[arg-type]
        )

        response = await commands.handle("user@example.com", "/contacts")

        self.assertIn("1. Alice", response.body)
        self.assertIn("/add <номер>", response.body)

    async def test_add_selected_contact_syncs_roster(self) -> None:
        roster = Roster()
        commands = XmppAuthenticationCommands(
            BackendId("max"),
            "max.example.com",
            Bindings(),  # type: ignore[arg-type]
            Authentication(),  # type: ignore[arg-type]
            sessions=Sessions(),  # type: ignore[arg-type]
            roster=roster,  # type: ignore[arg-type]
        )

        response = await commands.handle("user@example.com", "/add 1")

        self.assertEqual("Контакт добавлен в Xabber: Alice", response.body)
        self.assertEqual(RemoteObjectId("chat-1"), roster.added[1].id)

    async def test_logout_stops_session_and_disables_binding(self) -> None:
        bindings = Bindings()
        sessions = Sessions()
        commands = XmppAuthenticationCommands(
            BackendId("max"),
            "max.example.com",
            bindings,  # type: ignore[arg-type]
            Authentication(),  # type: ignore[arg-type]
            sessions=sessions,  # type: ignore[arg-type]
        )

        response = await commands.handle("user@example.com", "/logout")

        self.assertIn("сессия удалена", response.body)
        self.assertEqual(BindingId("binding-1"), sessions.stopped)
        self.assertEqual(BindingId("binding-1"), bindings.disabled)

    async def test_password_is_submitted_through_control_flow(self) -> None:
        authentication = Authentication()
        commands = XmppAuthenticationCommands(
            BackendId("max"),
            "max.example.com",
            Bindings(),  # type: ignore[arg-type]
            authentication,  # type: ignore[arg-type]
        )

        response = await commands.handle("user@example.com", "/password private")

        self.assertEqual("MAX успешно подключён.", response.body)
        self.assertEqual("private", authentication.responses[0][2].secret)

    async def test_background_password_notice_is_sent_from_control_jid(self) -> None:
        wire = Wire()
        notices = XmppAuthenticationNotices(
            "bot@max.example.com",
            Bindings(),  # type: ignore[arg-type]
            wire,
            XmppMessageCodec(),
        )

        await notices.deliver(
            BindingId("binding-1"), AuthChallenge(AuthState.WAITING_PASSWORD)
        )

        stanza = wire.sent[0]
        self.assertEqual("bot@max.example.com", stanza.attrib["from"])
        self.assertEqual("user@example.com", stanza.attrib["to"])
        self.assertIn("/password", stanza.findtext("body"))
