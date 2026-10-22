"""Small backend contracts; optional features are separate protocols."""

from dataclasses import dataclass
from typing import Mapping, Optional, Protocol, Sequence, Type, TypeVar, runtime_checkable

from xmpp_transport.domain.auth import AuthChallenge, AuthResponse
from xmpp_transport.domain.identifiers import BackendId, BindingId, RemoteObjectId
from xmpp_transport.domain.models import Contact, Conversation, OutgoingMessage

from .events import BackendEventSink

FeatureT = TypeVar("FeatureT")


@dataclass(frozen=True)
class SendResult:
    remote_message_id: RemoteObjectId


class MessageSender(Protocol):
    async def send_message(self, message: OutgoingMessage) -> SendResult:
        ...


class ContactSource(Protocol):
    async def contacts(self) -> Sequence[Contact]:
        ...


class ContactAdder(Protocol):
    async def add_contact_by_phone(self, phone: str) -> Contact:
        ...


class ButtonActions(Protocol):
    async def activate_button(
        self,
        conversation_id: RemoteObjectId,
        callback_id: str,
        payload: str,
        button_type: str,
    ) -> None:
        ...


class ConversationSource(Protocol):
    async def conversations(self) -> Sequence[Conversation]:
        ...


class BackendSession(Protocol):
    @property
    def binding_id(self) -> BindingId:
        ...

    async def start(self) -> None:
        ...

    async def close(self) -> None:
        ...

    def features(self) -> Mapping[type, object]:
        """Return implemented optional feature ports keyed by protocol type."""
        ...


class AuthenticationFlow(Protocol):
    async def start(self) -> AuthChallenge:
        ...

    async def respond(self, response: AuthResponse) -> AuthChallenge:
        ...

    async def close(self) -> None:
        ...

    def credentials(self) -> bytes:
        """Return provider credentials only after the flow reaches CONNECTED."""
        ...


@runtime_checkable
class ExclusiveAccountFlow(Protocol):
    def remote_account_id(self) -> str:
        """Return the personal account ID after authentication completes."""
        ...

    def matches_account(self, credentials: bytes) -> bool:
        """Compare legacy credentials with the authenticated personal account."""
        ...


class BackendPlugin(Protocol):
    @property
    def backend_id(self) -> BackendId:
        ...

    def create_authentication(self, binding_id: BindingId) -> AuthenticationFlow:
        ...

    def create_session(
        self, binding_id: BindingId, credentials: bytes, event_sink: BackendEventSink
    ) -> BackendSession:
        ...


class BackendFeatureProvider(Protocol):
    async def feature(
        self, binding_id: BindingId, feature_type: Type[FeatureT]
    ) -> Optional[FeatureT]:
        """Return an active binding feature, or None when it is unavailable."""
        ...


class BackendPluginProvider(Protocol):
    def get(self, backend_id: BackendId) -> BackendPlugin:
        ...
