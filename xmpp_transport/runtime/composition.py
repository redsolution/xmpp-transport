"""Composition root for one fault-isolated backend process."""

import asyncio
import logging
import os

from typing import Mapping, Optional

from xmpp_transport.adapters.events import InMemoryEventBus
from xmpp_transport.adapters.postgres import (
    AsyncpgBindingRepository,
    AsyncpgMessageMappingRepository,
    AsyncpgRosterSyncRepository,
    PostgresPoolManager,
)
from xmpp_transport.adapters.security import FernetCredentialCipher
from xmpp_transport.adapters.web import AiohttpHealthServer, QrCodeStore
from xmpp_transport.adapters.xmpp import (
    ComponentSettings,
    ContactAddressCodec,
    DirectRouteResolver,
    SlixmppComponentWire,
    XmppDirectMessageGateway,
    XmppGroupManager,
    XmppAuthenticationCommands,
    XmppAuthenticationNotices,
    XmppMessageCodec,
    XmppMessageDelivery,
    XmppServerRoster,
)
from xmpp_transport.application import (
    AuthenticationCoordinator,
    BackendEventDispatcher,
    ConversationSync,
    MessageRouter,
    RosterSync,
    SessionSupervisor,
)
from xmpp_transport.domain.errors import FeatureUnavailable
from xmpp_transport.domain.events import (
    AuthorizationLost,
    ContactChanged,
    ConversationChanged,
    MessageChanged,
    MessageReceived,
    SessionStateChanged,
)
from xmpp_transport.domain.identifiers import BackendId
from xmpp_transport.ports.backend import BackendPlugin, ContactAdder
from xmpp_transport.ports.events import BackendEventSink
from xmpp_transport.ports.xmpp import XmppRoster

from .config import BackendConfig, RuntimeConfig
from .health import HealthState
from .lifecycle import ApplicationRuntime
from .registry import BackendRegistry


log = logging.getLogger(__name__)


class EventSinkRelay:
    """Break the construction cycle, then permanently delegate to the event bus."""

    def __init__(self) -> None:
        self._sink: Optional[BackendEventSink] = None

    def bind(self, sink: BackendEventSink) -> None:
        if self._sink is not None:
            raise RuntimeError("event sink relay is already bound")
        self._sink = sink

    async def publish(self, event) -> None:  # type: ignore[no-untyped-def]
        if self._sink is None:
            raise RuntimeError("event sink relay is not bound")
        await self._sink.publish(event)


class SingleBackendRuntime:
    def __init__(
        self,
        config: RuntimeConfig,
        backend: BackendConfig,
        plugin: BackendPlugin,
        database: PostgresPoolManager,
        health: HealthState,
        health_server: AiohttpHealthServer,
        wire: SlixmppComponentWire,
        cipher: FernetCredentialCipher,
        qr_store: QrCodeStore,
        roster: Optional[XmppRoster] = None,
    ) -> None:
        if plugin.backend_id != BackendId(backend.name):
            raise ValueError("backend configuration does not match plugin identity")
        self._config = config
        self._backend = backend
        self._plugin = plugin
        self._database = database
        self._health = health
        self._health_server = health_server
        self._wire = wire
        self._cipher = cipher
        self._qr_store = qr_store
        self._roster = roster
        self._application: Optional[ApplicationRuntime] = None
        self._authentication: Optional[AuthenticationCoordinator] = None
        self._closed = False

    @property
    def health(self) -> HealthState:
        return self._health

    @property
    def authentication(self) -> AuthenticationCoordinator:
        if self._authentication is None:
            raise RuntimeError("runtime authentication is not initialized")
        return self._authentication

    async def start(self) -> None:
        if self._closed:
            raise RuntimeError("single backend runtime is closed")
        if self._application is not None:
            return
        try:
            pool = await self._database.start()
            application, authentication = self._build_application(pool)
            self._application = application
            self._authentication = authentication
            await application.start()
        except BaseException:
            self._health.mark_failed()
            raise

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        application = self._application
        self._application = None
        self._authentication = None
        if application is not None:
            await application.close()
            return
        self._health.mark_stopping()
        await self._database.close()
        await self._health_server.close()

    def _build_application(self, pool):  # type: ignore[no-untyped-def]
        bindings = AsyncpgBindingRepository(pool, backend_id=self._plugin.backend_id)
        mappings = AsyncpgMessageMappingRepository(pool)
        registry = BackendRegistry((self._plugin,))
        relay = EventSinkRelay()
        sessions = SessionSupervisor(registry, bindings, self._cipher, relay)

        addresses = ContactAddressCodec(self._backend.component_jid)
        codec = XmppMessageCodec()
        control_localpart = self._backend.options.get("control_localpart", "bot")
        server_domain = self._backend.options.get(
            "server_domain", _server_domain(self._backend.component_jid)
        )
        transport_namespace = "urn:xabber:transport:{}:1".format(
            self._backend.name
        )
        roster_namespace = self._backend.options.get(
            "roster_namespace", "urn:xabber:transport:roster:1"
        )
        iq_auth_secret = self._config.iq_auth_secret
        delivery = XmppMessageDelivery(
            self._wire,
            addresses,
            bindings,
            codec,
            server_domain=server_domain,
            control_jid="{}@{}".format(control_localpart, self._backend.component_jid),
            transport_namespace=transport_namespace,
            group_localpart_prefix="{}g".format(self._backend.name),
            member_fallback_prefix=self._backend.name,
        )
        messages = MessageRouter(sessions, mappings, delivery)
        routes = DirectRouteResolver(self._plugin.backend_id, addresses, bindings)
        dispatcher = BackendEventDispatcher()
        dispatcher.register(MessageReceived, messages.receive)
        dispatcher.register(
            AuthorizationLost,
            self._authorization_lost_handler(sessions, bindings),
        )
        dispatcher.register(SessionStateChanged, self._observe_session_state)
        dispatcher.register(MessageChanged, self._unsupported_event)
        roster = self._roster or XmppServerRoster(
            self._wire,
            bindings,
            addresses,
            self._backend.component_jid,
            server_domain,
            roster_namespace,
            (
                self._backend.options.get(
                    "roster_group",
                    "Telegram"
                    if self._backend.name == "telegram"
                    else self._backend.name.upper(),
                ),
            ),
            iq_auth_secret,
        )
        roster_sync = RosterSync(AsyncpgRosterSyncRepository(pool), roster)
        dispatcher.register(ContactChanged, roster_sync.handle)
        group_sync = ConversationSync(
            XmppGroupManager(
                self._wire,
                bindings,
                self._backend.component_jid,
                server_domain,
                control_localpart,
                "{}g".format(self._backend.name),
                self._backend.name.upper(),
            )
        )
        dispatcher.register(ConversationChanged, group_sync.handle)

        event_bus = InMemoryEventBus(dispatcher)
        relay.bind(event_bus)
        notices = XmppAuthenticationNotices(
            "{}@{}".format(control_localpart, self._backend.component_jid),
            bindings,
            self._wire,
            codec,
            self._backend.name.upper(),
        )
        authentication = AuthenticationCoordinator(
            registry,
            bindings,
            self._cipher,
            sessions,
            challenge_handler=notices.deliver,
        )
        control = XmppAuthenticationCommands(
            self._plugin.backend_id,
            self._backend.component_jid,
            bindings,
            authentication,
            control_localpart=control_localpart,
            sessions=sessions,
            roster=roster,
            contacts_page_size=_positive_int(
                self._backend.options.get("contacts_page_size", "20"),
                "contacts_page_size",
            ),
            provider_name=self._backend.name.upper(),
            supports_phone_contact_addition=ContactAdder
            in getattr(self._plugin, "supported_features", ()),
            qr_store=self._qr_store,
        )
        gateway = XmppDirectMessageGateway(
            self._wire,
            routes,
            addresses,
            bindings,
            messages,
            codec,
            control=control,
            transport_namespace=transport_namespace,
            server_domain=server_domain,
            group_localpart_prefix="{}g".format(self._backend.name),
        )
        application = ApplicationRuntime(
            self._health,
            self._health_server,
            self._database,
            sessions,
            event_bus,
            gateways=(gateway,),
            background_resources=(self._qr_store,),
            managed_resources=(authentication,),
        )
        return application, authentication

    @staticmethod
    def _authorization_lost_handler(
        sessions: SessionSupervisor, bindings: AsyncpgBindingRepository
    ):  # type: ignore[no-untyped-def]
        async def handle(event: AuthorizationLost) -> None:
            await bindings.mark_authorization_lost(event.envelope.binding_id)
            # start() can still own this binding lock when authorization is
            # rejected. Deferred stop avoids deadlocking event publication.
            task = asyncio.create_task(sessions.stop(event.envelope.binding_id))
            task.add_done_callback(SingleBackendRuntime._log_background_failure)

        return handle

    @staticmethod
    def _log_background_failure(task: asyncio.Task) -> None:
        try:
            task.result()
        except asyncio.CancelledError:
            return
        except Exception:
            log.exception("Stopping unauthorized backend session failed")

    @staticmethod
    async def _observe_session_state(event: SessionStateChanged) -> None:
        # Registration is intentional. Metrics/log projection is added separately.
        return None

    @staticmethod
    async def _unsupported_event(event) -> None:  # type: ignore[no-untyped-def]
        raise FeatureUnavailable(
            "event is not supported by the current vertical slice: {}".format(
                event.envelope.event_type
            )
        )


def compose_single_backend(
    config: RuntimeConfig,
    plugin: BackendPlugin,
    environment: Optional[Mapping[str, str]] = None,
    roster: Optional[XmppRoster] = None,
) -> SingleBackendRuntime:
    if len(config.backends) != 1:
        raise ValueError("single-backend runtime requires exactly one backend section")
    if config.database is None:
        raise ValueError("single-backend runtime requires [database] configuration")
    backend = config.backends[0]
    iq_auth_secret = config.iq_auth_secret
    if len(iq_auth_secret.encode("utf-8")) < 32:
        raise ValueError("iq_auth_secret must contain at least 32 bytes")
    configure_plugin = getattr(plugin, "configure", None)
    if configure_plugin is not None:
        configure_plugin(backend.options)
    secret_environment = backend.options.get(
        "component_password_env",
        "XABBER_TRANSPORT_{}_COMPONENT_PASSWORD".format(backend.name.upper().replace("-", "_")),
    )
    source = environment if environment is not None else os.environ
    component_password = backend.component_password or source.get(secret_environment)
    if not component_password:
        raise ValueError(
            "XMPP component password environment variable is not set: {}".format(
                secret_environment
            )
        )
    component = ComponentSettings(
        domain=backend.component_jid,
        secret=component_password,
        host=backend.options.get("server_ip", "127.0.0.1"),
        port=_positive_int(backend.options.get("server_port", "5347"), "server_port"),
        connect_timeout=_positive_float(
            backend.options.get("component_connect_timeout", "15"),
            "component_connect_timeout",
        ),
        reconnect_delay=_positive_float(
            backend.options.get("component_reconnect_delay", "5"),
            "component_reconnect_delay",
        ),
    )
    http_host = backend.options.get("http_host", config.http.host).strip()
    if not http_host:
        raise ValueError("http_host must not be empty")
    http_port = _positive_int(
        backend.options.get("http_port", str(config.http.port)),
        "http_port",
    )
    if http_port > 65535:
        raise ValueError("http_port must be at most 65535")
    qr_storage_dir = backend.options.get(
        "qr_storage_dir", "data/login_qr/{}".format(backend.name)
    ).strip()
    if not qr_storage_dir:
        raise ValueError("qr_storage_dir must not be empty")
    qr_base_url = backend.options.get(
        "qr_base_url", _default_http_base_url(http_host, http_port)
    ).strip().rstrip("/")
    if not qr_base_url.startswith(("http://", "https://")):
        raise ValueError("qr_base_url must use HTTP or HTTPS")
    qr_store = QrCodeStore(
        qr_storage_dir,
        qr_base_url,
        backend.name,
        max_age_seconds=_nonnegative_int(
            backend.options.get("qr_max_age_seconds", "3600"),
            "qr_max_age_seconds",
        ),
        cleanup_interval_seconds=_positive_int(
            backend.options.get("qr_cleanup_interval_seconds", "3600"),
            "qr_cleanup_interval_seconds",
        ),
    )
    health = HealthState()
    return SingleBackendRuntime(
        config=config,
        backend=backend,
        plugin=plugin,
        database=PostgresPoolManager(config.database.resolve(source)),
        health=health,
        health_server=AiohttpHealthServer(
            health,
            http_host,
            http_port,
            media_handler=getattr(plugin, "media_handler", None),
            avatar_handler=getattr(plugin, "avatar_handler", None),
            qr_storage_dir=qr_storage_dir,
        ),
        wire=SlixmppComponentWire(component),
        cipher=FernetCredentialCipher(config.credential_key(environment)),
        qr_store=qr_store,
        roster=roster,
    )


def _positive_int(value: str, name: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise ValueError("{} must be an integer".format(name)) from None
    if parsed <= 0:
        raise ValueError("{} must be positive".format(name))
    return parsed


def _nonnegative_int(value: str, name: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise ValueError("{} must be an integer".format(name)) from None
    if parsed < 0:
        raise ValueError("{} must not be negative".format(name))
    return parsed


def _default_http_base_url(host: str, port: int) -> str:
    public_host = "127.0.0.1" if host in ("", "0.0.0.0", "::") else host
    return "http://{}:{}".format(public_host, port)


def _server_domain(component_domain: str) -> str:
    _prefix, separator, server_domain = component_domain.partition(".")
    return server_domain if separator else component_domain


def _positive_float(value: str, name: str) -> float:
    try:
        parsed = float(value)
    except ValueError:
        raise ValueError("{} must be a number".format(name)) from None
    if parsed <= 0:
        raise ValueError("{} must be positive".format(name))
    return parsed
