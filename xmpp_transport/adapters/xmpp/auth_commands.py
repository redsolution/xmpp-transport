"""XMPP control-chat commands for provider authentication."""

from dataclasses import dataclass, field
from typing import Optional, Protocol, Sequence

from xmpp_transport.application.authentication import AuthenticationCoordinator
from xmpp_transport.domain.auth import AuthChallenge, AuthResponse, AuthResponseKind, AuthState
from xmpp_transport.domain.identifiers import BackendId, BindingId
from xmpp_transport.ports.backend import BackendFeatureProvider, ContactAdder, ContactSource
from xmpp_transport.ports.repositories import BindingRepository
from xmpp_transport.ports.xmpp import XmppRoster

from .addressing import bare_jid


@dataclass(frozen=True)
class ControlMedia:
    name: str
    mime_type: str
    uri: str = field(repr=False)
    size: int


class StoredQrImage(Protocol):
    @property
    def url(self) -> str:
        ...

    @property
    def name(self) -> str:
        ...

    @property
    def mime_type(self) -> str:
        ...

    @property
    def size(self) -> int:
        ...


class QrImageStore(Protocol):
    def create(self, value: str) -> StoredQrImage:
        ...


@dataclass(frozen=True)
class ControlResponse:
    body: str
    media: Sequence[ControlMedia] = field(default_factory=tuple)
    buttons: Sequence[Sequence["ControlButton"]] = field(default_factory=tuple)
    forms: Sequence["ControlForm"] = field(default_factory=tuple)


@dataclass(frozen=True)
class ControlButton:
    label: str
    data: str
    type: str = "command"


@dataclass(frozen=True)
class ControlFormField:
    name: str
    label: str = ""
    type: str = "text-single"
    value: str = ""
    required: bool = False


@dataclass(frozen=True)
class ControlForm:
    title: str
    instructions: str
    fields: Sequence[ControlFormField]


class XmppAuthenticationCommands:
    def __init__(
        self,
        backend_id: BackendId,
        component_domain: str,
        bindings: BindingRepository,
        authentication: AuthenticationCoordinator,
        control_localpart: str = "bot",
        sessions: Optional[BackendFeatureProvider] = None,
        roster: Optional[XmppRoster] = None,
        contacts_page_size: int = 20,
        provider_name: Optional[str] = None,
        supports_phone_contact_addition: bool = False,
        qr_store: Optional[QrImageStore] = None,
    ) -> None:
        self._backend_id = backend_id
        self._provider_name = provider_name or str(backend_id).upper()

        localpart = control_localpart.strip().lower()
        if not localpart or "@" in localpart or "/" in localpart:
            raise ValueError("control localpart is invalid")
        self._control_jid = "{}@{}".format(
            localpart, component_domain.strip().lower()
        )
        self._bindings = bindings
        self._authentication = authentication
        self._sessions = sessions
        self._roster = roster
        self._contacts_page_size = contacts_page_size
        self._supports_phone_contact_addition = supports_phone_contact_addition
        self._qr_store = qr_store

    def accepts(self, to_jid: str) -> bool:
        return to_jid.split("/", 1)[0].strip().lower() == self._control_jid

    async def handle(
        self,
        from_jid: str,
        command: str,
        form_fields: Optional[dict] = None,
    ) -> ControlResponse:
        if form_fields:
            if form_fields.get("command", "").strip().lower() != "password":
                return self._response("Неизвестная форма.")
            command = "/password {}".format(form_fields.get("password", ""))
        value = command.strip()
        command_name, _, argument = value.partition(" ")
        command_name = command_name.lower()
        owner = bare_jid(from_jid)
        if command_name in ("/help", "/?") or not command_name.startswith("/"):
            return self._response(self.help_text())
        if command_name == "/status":
            return self._response(await self._status(owner))
        if command_name == "/logout":
            return self._response(await self._logout(owner))
        if command_name == "/contacts":
            return await self._contacts(owner, argument)
        if command_name == "/sync-contacts":
            return self._response(await self._sync_contacts(owner))
        if command_name == "/add":
            return self._response(await self._add(owner, argument))
        if command_name not in ("/login", "/password"):
            return self._response("Неизвестная команда.\n\n" + self.help_text())
        if command_name == "/login":
            binding = await self._bindings.ensure_binding(owner, self._backend_id)
            challenge = await self._authentication.begin(
                binding.binding_id, self._backend_id
            )
        else:
            binding = await self._bindings.binding_for_authentication(
                owner, self._backend_id
            )
            if binding is None:
                raise LookupError("binding is not available for authentication")
        if command_name == "/password":
            if not argument:
                binding = await self._bindings.binding_for_authentication(
                    owner, self._backend_id
                )
                if (
                    binding is None
                    or self._authentication.state(binding.binding_id)
                    is not AuthState.WAITING_PASSWORD
                ):
                    return self._response(
                        "MAX сейчас не ожидает пароль 2FA. "
                        "Отправьте /login, чтобы начать авторизацию."
                    )
                return self._password_form()
            challenge = await self._authentication.respond(
                binding.binding_id,
                self._backend_id,
                AuthResponse(AuthResponseKind.PASSWORD, argument),
            )
        if challenge.state is AuthState.WAITING_QR:
            if not challenge.public_url:
                return self._response("MAX не вернул данные для QR-кода.")
            if self._qr_store is None:
                raise RuntimeError("login QR storage is not configured")
            return ControlResponse(
                self._provider_text(
                    "Отсканируйте QR-код приложением MAX.\n"
                    "После подтверждения transport сообщит о результате здесь."
                ),
                (_qr_media(self._qr_store.create(challenge.public_url)),),
                buttons=self._main_menu_buttons(),
            )
        if challenge.state is AuthState.WAITING_PASSWORD:
            return self._response("MAX запросил пароль 2FA. Отправьте /password <пароль>.")
        if challenge.state is AuthState.CONNECTED:
            return self._response("MAX успешно подключён.")
        return self._response(challenge.message or "Авторизация MAX завершилась с ошибкой.")

    async def _active(self, owner: str):  # type: ignore[no-untyped-def]
        binding = await self._bindings.binding_for_authentication(owner, self._backend_id)
        if binding is None or self._sessions is None:
            return binding, None
        feature = await self._sessions.feature(binding.binding_id, ContactSource)
        return binding, feature

    async def _status(self, owner: str) -> str:
        binding, contacts = await self._active(owner)
        if binding is None:
            return "MAX не подключен. Отправьте /login для авторизации."
        if contacts is not None:
            return "MAX подключен."
        return "MAX-сессия сохранена, но сейчас не подключена."

    async def _contacts(self, owner: str, argument: str) -> ControlResponse:
        binding, source = await self._active(owner)
        if binding is None or source is None:
            return self._response("MAX не подключен. Отправьте /login для авторизации.")
        try:
            page = int(argument) if argument else 1
        except ValueError:
            return self._response("Номер страницы должен быть целым числом.")
        if page < 1:
            return self._response("Используйте: /contacts [страница]")
        contacts = tuple(await source.contacts())
        if not contacts:
            return self._response("В MAX нет сохраненных контактов.")
        start = (page - 1) * self._contacts_page_size
        if start >= len(contacts):
            return self._response("Такой страницы контактов нет.")
        shown = contacts[start : start + self._contacts_page_size]
        total = (len(contacts) + self._contacts_page_size - 1) // self._contacts_page_size
        lines = ["Контакты MAX, страница {}/{}:".format(page, total)]
        lines.extend(
            "{}. {}".format(start + index, contact.display_name)
            for index, contact in enumerate(shown, start=1)
        )
        lines.extend(("", "Добавить в Xabber: /add <номер>"))
        if page < total:
            lines.append("Следующая страница: /contacts {}".format(page + 1))
        if self._supports_phone_contact_addition:
            lines.append("Добавить по телефону: /add phone +79990000000")
        rows = []
        navigation = []
        if page > 1:
            navigation.append(ControlButton("Назад", "/contacts {}".format(page - 1)))
        if page < total:
            navigation.append(ControlButton("Дальше", "/contacts {}".format(page + 1)))
        if navigation:
            rows.append(tuple(navigation))
        rows.extend(
            (ControlButton("Добавить: {}".format(contact.display_name), "/add {}".format(start + index)),)
            for index, contact in enumerate(shown, start=1)
        )
        rows.extend(self._main_menu_buttons())
        return ControlResponse(self._provider_text("\n".join(lines)), buttons=tuple(rows))

    async def _add(self, owner: str, argument: str) -> str:
        binding, source = await self._active(owner)
        if binding is None or source is None or self._roster is None:
            return "MAX не подключен. Отправьте /login для авторизации."
        if argument.lower().startswith("phone "):
            if not self._supports_phone_contact_addition:
                return "Добавление контакта по телефону недоступно."
            adder = await self._sessions.feature(binding.binding_id, ContactAdder)  # type: ignore[union-attr]
            if adder is None:
                return "Добавление контакта по телефону недоступно."
            phone = argument[6:].strip()
            if not phone:
                return "Используйте: /add phone +79990000000"
            contact = await adder.add_contact_by_phone(phone)
        else:
            try:
                selection = int(argument)
            except ValueError:
                if self._supports_phone_contact_addition:
                    return "Используйте: /add <номер> или /add phone +79990000000"
                return "Используйте: /add <номер>"
            contacts = tuple(await source.contacts())
            if selection < 1 or selection > len(contacts):
                return "Контакт с таким номером отсутствует в списке."
            contact = contacts[selection - 1]
        await self._roster.add_contact(binding.binding_id, contact)
        return "Контакт добавлен в Xabber: {}".format(contact.display_name)

    async def _sync_contacts(self, owner: str) -> str:
        binding, source = await self._active(owner)
        if binding is None or source is None or self._roster is None:
            return "{} не подключен. Отправьте /login для авторизации.".format(
                self._provider_name
            )
        contacts = tuple(await source.contacts())
        for contact in contacts:
            await self._roster.add_contact(binding.binding_id, contact)
        return "Синхронизировано контактов {}: {}.".format(
            self._provider_name, len(contacts)
        )

    async def _logout(self, owner: str) -> str:
        binding = await self._bindings.binding_for_authentication(owner, self._backend_id)
        if binding is None:
            return "MAX не подключен. Отправьте /login для авторизации."
        await self._authentication.cancel(binding.binding_id)
        if self._sessions is not None:
            await self._sessions.stop(binding.binding_id)  # type: ignore[attr-defined]
        await self._bindings.disable_binding(binding.binding_id)
        return "MAX отключен, сохраненная сессия удалена."

    def help_text(self) -> str:
        lines = [
            "Команды MAX transport:\n"
            "/login - подключить MAX-аккаунт через QR\n"
            "/password <пароль> - продолжить login при включенной 2FA\n"
            "/status - проверить состояние подключения\n"
            "/contacts [страница] - показать контакты MAX\n"
            "/sync-contacts - повторно синхронизировать контакты\n"
            "/add <номер> - добавить выбранный контакт в Xabber"
        ]
        if self._supports_phone_contact_addition:
            lines.append("/add phone +79990000000 - добавить контакт MAX по телефону")
        lines.extend(
            (
                "/logout - отключить MAX и удалить сохраненную сессию",
                "/help - показать команды",
            )
        )
        return "\n".join(lines)

    def _response(self, body: str) -> ControlResponse:
        return ControlResponse(
            self._provider_text(body), buttons=self._main_menu_buttons()
        )

    def _provider_text(self, value: str) -> str:
        return value.replace("MAX", self._provider_name)

    def _main_menu_buttons(self):  # type: ignore[no-untyped-def]
        return (
            (
                ControlButton("Подключить {}".format(self._provider_name), "/login"),
                ControlButton("Статус", "/status"),
            ),
            (
                ControlButton("Контакты", "/contacts"),
                ControlButton("Отключить", "/logout"),
            ),
            (ControlButton("Синхронизировать", "/sync-contacts"),),
            (
                ControlButton("Пароль 2FA", "/password"),
                ControlButton("Помощь", "/help"),
            ),
        )

    def _password_form(self) -> ControlResponse:
        return ControlResponse(
            self._provider_text(
                "MAX запросил пароль двухфакторной авторизации.\n"
                "Введите пароль в форме. Transport передаст его MAX однократно и не сохранит."
            ),
            buttons=self._main_menu_buttons(),
            forms=(
                ControlForm(
                    self._provider_text("Пароль MAX 2FA"),
                    self._provider_text("Введите пароль MAX для продолжения авторизации."),
                    (
                        ControlFormField("command", type="hidden", value="password"),
                        ControlFormField(
                            "password", label="Пароль", type="text-private", required=True
                        ),
                    ),
                ),
            ),
        )

class XmppAuthenticationNotices:
    def __init__(
        self,
        control_jid: str,
        bindings: BindingRepository,
        wire,  # type: ignore[no-untyped-def]
        codec,  # type: ignore[no-untyped-def]
        provider_name: str = "MAX",
    ) -> None:
        self._control_jid = control_jid
        self._bindings = bindings
        self._wire = wire
        self._codec = codec
        self._provider_name = provider_name
    async def deliver(self, binding_id: BindingId, challenge: AuthChallenge) -> None:
        owner_jid = await self._bindings.xmpp_account_for_authentication(binding_id)
        if owner_jid is None:
            raise LookupError("XMPP account not found for authentication binding")
        if challenge.state is AuthState.WAITING_PASSWORD:
            body = "MAX запросил пароль 2FA. Отправьте /password <пароль>."
        elif challenge.state is AuthState.CONNECTED:
            body = "MAX успешно подключён."
        else:
            body = challenge.message or "Авторизация MAX завершилась с ошибкой."
        await self._wire.send(
            self._codec.control_notice(
                self._control_jid, owner_jid, ControlResponse(body.replace("MAX", self._provider_name))
            )
        )


def _qr_media(image: StoredQrImage) -> ControlMedia:
    return ControlMedia(
        name=image.name,
        mime_type=image.mime_type,
        uri=image.url,
        size=image.size,
    )
