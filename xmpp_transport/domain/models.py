"""Canonical models exchanged between adapters and application services."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Mapping, Optional, Sequence

from .identifiers import BindingId, RemoteObjectId


class ConversationKind(str, Enum):
    DIRECT = "direct"
    GROUP = "group"
    CHANNEL = "channel"


class MediaKind(str, Enum):
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    FILE = "file"
    STICKER = "sticker"


@dataclass(frozen=True)
class RemoteAccount:
    id: RemoteObjectId
    display_name: str
    username: Optional[str] = None


@dataclass(frozen=True)
class Avatar:
    reference: str
    version: Optional[str] = None
    content_type: str = "image/jpeg"
    size: int = 0


@dataclass(frozen=True)
class Contact:
    id: RemoteObjectId
    display_name: str
    username: Optional[str] = None
    avatar: Optional[Avatar] = None


@dataclass(frozen=True)
class Participant:
    id: RemoteObjectId
    display_name: str
    is_admin: bool = False


@dataclass(frozen=True)
class Conversation:
    id: RemoteObjectId
    kind: ConversationKind
    title: str
    participants: Sequence[Participant] = field(default_factory=tuple)
    avatar: Optional[Avatar] = None
    attributes: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Media:
    id: RemoteObjectId
    kind: MediaKind
    content_type: Optional[str] = None
    file_name: Optional[str] = None
    size: Optional[int] = None
    source_url: Optional[str] = field(default=None, repr=False)
    thumbnail_url: Optional[str] = field(default=None, repr=False)
    width: Optional[int] = None
    height: Optional[int] = None
    duration: Optional[int] = None
    voice: bool = False


@dataclass(frozen=True)
class ReplyReference:
    message_id: RemoteObjectId
    body: Optional[str] = None
    sender_id: Optional[RemoteObjectId] = None
    is_self: bool = False
    media: Sequence[Media] = field(default_factory=tuple)
    candidate_ids: Sequence[RemoteObjectId] = field(default_factory=tuple)


@dataclass(frozen=True)
class ForwardReference:
    source_name: Optional[str] = None
    source_message_id: Optional[RemoteObjectId] = None
    source_conversation_id: Optional[RemoteObjectId] = None
    sender_id: Optional[RemoteObjectId] = None
    body: Optional[str] = None
    media: Sequence[Media] = field(default_factory=tuple)
    source_recipient: Optional[str] = None
    is_self: bool = False
    source_message_ids: Sequence[RemoteObjectId] = field(default_factory=tuple)


@dataclass(frozen=True)
class MessageButton:
    text: str
    payload: str
    callback_id: Optional[str] = None
    kind: str = "CALLBACK"


@dataclass(frozen=True)
class IncomingMessage:
    id: RemoteObjectId
    binding_id: BindingId
    conversation_id: RemoteObjectId
    sender_id: RemoteObjectId
    occurred_at: datetime
    text: Optional[str] = None
    media: Sequence[Media] = field(default_factory=tuple)
    reply_to: Optional[ReplyReference] = None
    forwarded_from: Optional[ForwardReference] = None
    buttons: Sequence[Sequence[MessageButton]] = field(default_factory=tuple)
    attributes: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class OutgoingMessage:
    client_message_id: str
    binding_id: BindingId
    conversation_id: RemoteObjectId
    text: Optional[str] = None
    media: Sequence[Media] = field(default_factory=tuple)
    reply_to: Optional[ReplyReference] = None
    forwarded_from: Optional[ForwardReference] = None
    attributes: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.client_message_id:
            raise ValueError("client_message_id must not be empty")
        if not self.text and not self.media and self.forwarded_from is None:
            raise ValueError("an outgoing message must contain text, media, or a forward")
