"""Thin, lazily imported slixmpp XEP-0114 wire client."""

import asyncio
import inspect
import logging
import ssl
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any, Callable, Optional
from xml.etree import ElementTree as ET

from .gateway import MessageHandler

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ComponentSettings:
    domain: str
    secret: str = field(repr=False)
    host: str = "127.0.0.1"
    port: int = 5347
    connect_timeout: float = 15.0
    reconnect_delay: float = 5.0
    tls: bool = False
    tls_server_name: Optional[str] = None
    tls_ca_file: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.domain.strip() or not self.secret:
            raise ValueError("component domain and secret are required")
        if not self.host.strip() or not 1 <= self.port <= 65535:
            raise ValueError("component endpoint is invalid")
        if self.connect_timeout <= 0:
            raise ValueError("component connect_timeout must be positive")
        if self.reconnect_delay <= 0:
            raise ValueError("component reconnect_delay must be positive")
        if self.tls and (self.tls_server_name is None or not self.tls_server_name.strip()):
            raise ValueError("component tls_server_name is required when TLS is enabled")
        if not self.tls and (self.tls_server_name is not None or self.tls_ca_file is not None):
            raise ValueError("component TLS options require TLS to be enabled")
        if self.tls_ca_file is not None:
            if not self.tls_ca_file.strip() or not Path(self.tls_ca_file).is_file():
                raise ValueError("component tls_ca_file must be an existing file")


class SlixmppComponentWire:
    def __init__(
        self,
        settings: ComponentSettings,
        client_factory: Optional[Callable[..., Any]] = None,
    ) -> None:
        self._settings = settings
        self._client_factory = client_factory
        self._handler: Optional[MessageHandler] = None
        self._client: Optional[Any] = None
        # asyncio primitives bind to the current loop on Python 3.9. Runtime
        # composition is synchronous, so create the event lazily in start().
        self._ready: Optional[asyncio.Event] = None
        self._disconnected: Optional[asyncio.Event] = None
        self._connection_task: Optional[asyncio.Task[None]] = None
        self._closed = False

    def set_message_handler(self, handler: MessageHandler) -> None:
        if self._client is not None:
            raise RuntimeError("message handler must be configured before start")
        self._handler = handler

    async def start(self) -> None:
        if self._closed:
            raise RuntimeError("XMPP component wire is closed")
        if self._connection_task is not None:
            return
        if self._handler is None:
            raise RuntimeError("XMPP message handler is not configured")

        self._ready = asyncio.Event()
        self._disconnected = asyncio.Event()
        task = asyncio.create_task(
            self._connection_loop(),
            name="xmpp-component-connection",
        )
        self._connection_task = task
        # Do not restore backend sessions until XMPP can accept their events.
        await self._ready.wait()

    async def send(self, element: ET.Element) -> None:
        client = self._connected_client()
        if element.tag.rsplit("}", 1)[-1] == "message":
            body = next(
                (
                    child
                    for child in element
                    if child.tag.rsplit("}", 1)[-1] == "body"
                ),
                None,
            )
            message = client.make_message(
                mfrom=element.attrib.get("from"),
                mto=element.attrib.get("to"),
                mtype=element.attrib.get("type"),
                mbody=body.text if body is not None else None,
            )
            for name, value in element.attrib.items():
                if name not in {"from", "to", "type"}:
                    message.xml.set(name, value)
            for child in element:
                if child is not body:
                    message.xml.append(child)
            message.send()
            return
        client.send_raw(ET.tostring(element, encoding="unicode"))

    async def request(self, element: ET.Element, timeout: float = 10.0) -> ET.Element:
        if element.tag.rsplit("}", 1)[-1] != "iq":
            raise ValueError("XMPP request must be an IQ stanza")
        client = self._connected_client()
        children = tuple(element)
        if len(children) != 1:
            raise ValueError("XMPP IQ request must contain one payload element")
        iq = client.make_iq_set(
            sub=children[0],
            ito=element.attrib.get("to"),
            ifrom=element.attrib.get("from"),
        )
        if element.attrib.get("id"):
            iq["id"] = element.attrib["id"]
        response = await iq.send(timeout=timeout)
        return response.xml

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        ready = self._ready
        if ready is not None:
            ready.clear()
        disconnected = self._disconnected
        if disconnected is not None:
            disconnected.set()
        task = self._connection_task
        self._connection_task = None
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        await self._disconnect_client()

    def _connected_client(self) -> Any:
        client = self._client
        ready = self._ready
        if client is None or ready is None or not ready.is_set():
            raise ConnectionError("XMPP component is not connected")
        if self._settings.tls and not self._has_tls(client):
            ready.clear()
            raise ConnectionError("XMPP component TLS connection is unavailable")
        return client

    @staticmethod
    def _has_tls(client: Any) -> bool:
        transport = getattr(client, "transport", None)
        return (
            transport is not None
            and transport.get_extra_info("ssl_object") is not None
        )

    async def _on_session_start(self, client: Any, event: object) -> None:
        if self._closed or client is not self._client:
            return
        if self._settings.tls and not self._has_tls(client):
            log.warning(
                "XMPP component session rejected domain=%s reason=tls_unavailable",
                self._settings.domain,
            )
            client.abort()
            return
        if self._ready is not None:
            self._ready.set()

    def _on_disconnected(self, client: Any, event: object) -> None:
        if client is not self._client:
            return
        if self._ready is not None:
            self._ready.clear()
        if self._disconnected is not None:
            self._disconnected.set()

    async def _on_message(self, client: Any, stanza: Any) -> None:
        if client is not self._client:
            return
        if self._ready is not None and self._ready.is_set() and self._handler is not None:
            if self._settings.tls and not self._has_tls(client):
                self._ready.clear()
                return
            await self._handler(stanza.xml)

    async def _connection_loop(self) -> None:
        while not self._closed:
            try:
                await self._connect_once()
                assert self._disconnected is not None
                await self._disconnected.wait()
                log.warning(
                    "XMPP component disconnected domain=%s; reconnecting",
                    self._settings.domain,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning(
                    "XMPP component connection failed domain=%s host=%s port=%s "
                    "exception_type=%s; retrying in %.1f seconds",
                    self._settings.domain,
                    self._settings.host,
                    self._settings.port,
                    type(exc).__name__,
                    self._settings.reconnect_delay,
                )
            finally:
                if self._ready is not None:
                    self._ready.clear()
                await self._disconnect_client()
            if not self._closed:
                await asyncio.sleep(self._settings.reconnect_delay)

    async def _connect_once(self) -> None:
        factory = self._client_factory
        if factory is None:
            from slixmpp import ComponentXMPP

            factory = ComponentXMPP
        assert self._ready is not None
        assert self._disconnected is not None
        self._disconnected.clear()
        client = factory(
            self._settings.domain,
            self._settings.secret,
            self._settings.host,
            self._settings.port,
        )
        self._configure_tls(client)
        client.add_event_handler("session_start", partial(self._on_session_start, client))
        client.add_event_handler("disconnected", partial(self._on_disconnected, client))
        client.add_event_handler("message", partial(self._on_message, client))
        self._client = client
        connected = client.connect()
        if inspect.isawaitable(connected):
            connected = await asyncio.wait_for(
                connected, timeout=self._settings.connect_timeout
            )
        if connected is False:
            raise ConnectionError("XMPP component connection was rejected")
        await asyncio.wait_for(
            self._ready.wait(), timeout=self._settings.connect_timeout
        )
        log.info(
            "XMPP component connected domain=%s host=%s port=%s",
            self._settings.domain,
            self._settings.host,
            self._settings.port,
        )

    def _configure_tls(self, client: Any) -> None:
        if not self._settings.tls:
            return
        # ComponentXMPP 1.10 defaults to plaintext. With a custom host/port,
        # XMLStream uses tls_services to select direct TLS. Clearing the other
        # modes makes a failed TLS handshake fail closed on every retry.
        client.tls_services = {"xmpps-component"}
        client.starttls_services.clear()
        client.enable_direct_tls = True
        client.enable_starttls = False
        client.enable_plaintext = False
        client.default_domain = self._settings.tls_server_name
        context = ssl.create_default_context(cafile=self._settings.tls_ca_file)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        client.ssl_context = context

    async def _disconnect_client(self) -> None:
        client = self._client
        self._client = None
        if client is None:
            return
        # Slixmpp keeps retrying a failed connection in the background.  A
        # timed-out client must not reconnect after a replacement is created:
        # ejabberd can route IQ replies to that abandoned component stream.
        cancel_attempt = getattr(client, "cancel_connection_attempt", None)
        if cancel_attempt is not None:
            cancel_attempt()
        result = client.disconnect()
        if inspect.isawaitable(result):
            await result
        # Slixmpp's outbound filter loop survives disconnect(), including
        # failed TLS handshakes. This client is never reused after a retry.
        filter_task = getattr(client, "_run_out_filters", None)
        if filter_task is not None and not filter_task.done():
            filter_task.cancel()
            await asyncio.gather(filter_task, return_exceptions=True)
