"""Thin, lazily imported slixmpp XEP-0114 wire client."""

import asyncio
import inspect
import logging
from dataclasses import dataclass, field
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

    def __post_init__(self) -> None:
        if not self.domain.strip() or not self.secret:
            raise ValueError("component domain and secret are required")
        if not self.host.strip() or not 1 <= self.port <= 65535:
            raise ValueError("component endpoint is invalid")
        if self.connect_timeout <= 0:
            raise ValueError("component connect_timeout must be positive")
        if self.reconnect_delay <= 0:
            raise ValueError("component reconnect_delay must be positive")


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
        client = self._client
        ready = self._ready
        if client is None or ready is None or not ready.is_set():
            raise ConnectionError("XMPP component is not connected")
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
        client = self._client
        ready = self._ready
        if client is None or ready is None or not ready.is_set():
            raise ConnectionError("XMPP component is not connected")
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

    async def _on_session_start(self, event: object) -> None:
        if self._ready is not None:
            self._ready.set()

    def _on_disconnected(self, event: object) -> None:
        if self._ready is not None:
            self._ready.clear()
        if self._disconnected is not None:
            self._disconnected.set()

    async def _on_message(self, stanza: Any) -> None:
        if self._handler is not None:
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
        client.add_event_handler("session_start", self._on_session_start)
        client.add_event_handler("disconnected", self._on_disconnected)
        client.add_event_handler("message", self._on_message)
        self._client = client
        connected = client.connect()
        if inspect.isawaitable(connected):
            connected = await connected
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

    async def _disconnect_client(self) -> None:
        client = self._client
        self._client = None
        if client is None:
            return
        result = client.disconnect()
        if inspect.isawaitable(result):
            await result
