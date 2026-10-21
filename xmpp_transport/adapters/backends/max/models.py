from dataclasses import dataclass
from typing import Optional

from xmpp_transport.domain.errors import AuthorizationRequired


class MaxAuthorizationError(AuthorizationRequired):
    def __init__(self, message: str, *, terminal: bool = False):
        super().__init__(message)
        self.terminal = terminal


@dataclass(frozen=True)
class MaxAvatar:
    url: str
    avatar_id: str
    mime_type: str = "image/jpeg"
    bytes: int = 0


@dataclass(frozen=True)
class MaxMedia:
    url: str
    name: str = ""
    mime_type: str = "application/octet-stream"
    size: int = 0
    thumbnail_url: Optional[str] = None
    width: Optional[int] = None
    height: Optional[int] = None
    duration: Optional[int] = None
    voice: bool = False


@dataclass(frozen=True)
class MaxButton:
    text: str
    payload: str
    callback_id: Optional[str] = None
    kind: str = "CALLBACK"


@dataclass(frozen=True)
class OutgoingMediaUpload:
    data: bytes
    name: str
    mime_type: str
    size: int
    width: Optional[int] = None
    height: Optional[int] = None
    duration: Optional[int] = None
    voice: bool = False


@dataclass(frozen=True)
class MaxForwardReference:
    source_chat_id: str
    message_id: str


@dataclass(frozen=True)
class MaxChat:
    chat_id: str
    title: str
    is_group: bool = False
    members: tuple["MaxChatMember", ...] = ()
    raw: Optional[dict] = None
    avatar: Optional[MaxAvatar] = None
    force_roster_sync: bool = False
    create_chat: bool = False


@dataclass(frozen=True)
class MaxChatMember:
    user_id: str
    title: str
    avatar: Optional[MaxAvatar] = None


@dataclass(frozen=True)
class MaxGroupMembersSync:
    chat: MaxChat
    removed_members: tuple["MaxChatMember", ...] = ()


@dataclass(frozen=True)
class MaxContact:
    contact_id: str
    title: str
    chat_id: str
    raw: Optional[dict] = None
    avatar: Optional[MaxAvatar] = None


@dataclass(frozen=True)
class MaxIncomingMessage:
    sender_id: str
    text: str
    chat_id: Optional[str] = None
    chat_title: Optional[str] = None
    sender_title: Optional[str] = None
    message_id: Optional[str] = None
    reply_to_message_id: Optional[str] = None
    is_self: bool = False
    is_group: bool = False
    media: tuple[MaxMedia, ...] = ()
    buttons: tuple[tuple[MaxButton, ...], ...] = ()
    raw: Optional[dict] = None
