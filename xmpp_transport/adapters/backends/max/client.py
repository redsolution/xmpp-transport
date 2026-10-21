import asyncio
import json
import logging
import mimetypes
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import replace
from typing import Awaitable, Callable, Optional
from urllib.parse import quote, urlsplit

from aiohttp import ClientSession, ClientTimeout, ClientWebSocketResponse, FormData, WSMsgType

from .auth import create_max_client_session, normalize_phone, web_client_headers, web_device_handshake
from .models import (
    MaxAuthorizationError,
    MaxAvatar,
    MaxButton,
    MaxChat,
    MaxChatMember,
    MaxContact,
    MaxForwardReference,
    MaxGroupMembersSync,
    MaxIncomingMessage,
    MaxMedia,
    OutgoingMediaUpload,
)
from .snapshot import MaxMessageDeduplicator, MaxSnapshotCache


log = logging.getLogger(__name__)

MaxMessageHandler = Callable[["MaxIncomingMessage"], Awaitable[None]]
MaxChatHandler = Callable[["MaxChat"], Awaitable[None]]
MaxAuthorizationLostHandler = Callable[[MaxAuthorizationError], Awaitable[None]]


class PersonalMaxBackend:
    OP_HEARTBEAT_PING = 1
    OP_HANDSHAKE = 6
    OP_AUTH_SNAPSHOT = 19
    OP_CONTACTS_GET = 32
    OP_CONTACT_ADD_BY_PHONE = 41
    OP_CHAT_MEMBERS = 59
    OP_MSG_SEND = 64
    OP_BUTTON_CALLBACK = 118
    OP_VIDEO_SOURCES = 83
    OP_PHOTO_UPLOAD = 80
    OP_VIDEO_UPLOAD = 82
    OP_FILE_UPLOAD = 87
    OP_FILE_DOWNLOAD = 88
    OP_DISPATCH = 128
    ATTACHMENT_NOT_READY_RETRY_DELAYS = (1, 2, 3, 5, 8, 8)

    def __init__(
        self,
        token: str,
        device_id: str,
        app_version: str = "26.5.10",
        initial_chats_count: int = 40,
        reconnect_delay: float = 5.0,
        seen_messages_limit: int = 2000,
    ):
        self.token = token
        self.device_id = device_id
        self.app_version = app_version
        self.initial_chats_count = initial_chats_count
        self.reconnect_delay = reconnect_delay
        self.seen_messages_limit = seen_messages_limit
        self.session: Optional[ClientSession] = None
        self.ws: Optional[ClientWebSocketResponse] = None
        self._message_handler: Optional[MaxMessageHandler] = None
        self._chat_handler: Optional[MaxChatHandler] = None
        self._authorization_lost_handler: Optional[MaxAuthorizationLostHandler] = None
        self._task: Optional[asyncio.Task] = None
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._snapshot_task: Optional[asyncio.Task] = None
        self._ready = asyncio.Event()
        self._startup_failed = asyncio.Event()
        self._startup_exception: Optional[BaseException] = None
        self._closed = asyncio.Event()
        self._send_lock = asyncio.Lock()
        self._chat_refresh_lock = asyncio.Lock()
        self._seq = 0
        self._pending: dict[int, asyncio.Future[dict]] = {}
        self._snapshot_cache = MaxSnapshotCache()
        self._unknown_chat_refresh_tasks: dict[str, asyncio.Task] = {}
        self._pending_unknown_chat_payloads: dict[str, list[dict]] = {}
        self._contacts_ready = asyncio.Event()
        self._deduplicator = MaxMessageDeduplicator(seen_messages_limit)
        self.my_id: Optional[str] = None

    def set_message_handler(self, handler: MaxMessageHandler) -> None:
        self._message_handler = handler

    def set_chat_handler(self, handler: MaxChatHandler) -> None:
        self._chat_handler = handler

    def set_authorization_lost_handler(self, handler: MaxAuthorizationLostHandler) -> None:
        self._authorization_lost_handler = handler

    def _schedule_authorization_lost(self, exc: MaxAuthorizationError) -> None:
        if self._authorization_lost_handler is None:
            return
        task = asyncio.create_task(self._authorization_lost_handler(exc))
        task.add_done_callback(self._log_authorization_lost_task_failure)

    @staticmethod
    def _log_authorization_lost_task_failure(task: asyncio.Task) -> None:
        try:
            task.result()
        except asyncio.CancelledError:
            pass
        except Exception:
            log.exception("MAX authorization-lost handler failed")

    async def start(self) -> None:
        self.session = create_max_client_session()
        self._task = asyncio.create_task(self._run_forever())
        ready_task = asyncio.create_task(self._ready.wait())
        failed_task = asyncio.create_task(self._startup_failed.wait())
        try:
            # start() returns only after the first successful authorization snapshot.
            # Later reconnects happen in the background inside _run_forever().
            done, _pending = await asyncio.wait(
                {ready_task, failed_task},
                timeout=20,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if ready_task in done and self._ready.is_set():
                return
            if failed_task in done and self._startup_exception is not None:
                raise self._startup_exception
            raise RuntimeError(
                "Timed out waiting for MAX personal authorization; "
                "send login to the transport contact to authorize again."
            )
        except BaseException:
            await self.close()
            raise
        finally:
            ready_task.cancel()
            failed_task.cancel()

    async def close(self) -> None:
        self._closed.set()
        # Cancel background tasks first so no new websocket sends are scheduled while
        # HTTP/WebSocket resources are being closed below.
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
        if self._snapshot_task is not None:
            self._snapshot_task.cancel()
        if self._task is not None:
            self._task.cancel()
        for task in self._unknown_chat_refresh_tasks.values():
            task.cancel()
        if self.ws is not None and not self.ws.closed:
            await self.ws.close()
        if self.session is not None:
            await self.session.close()
        for future in self._pending.values():
            if not future.done():
                # Pending opcode requests cannot complete after the socket is closed.
                future.cancel()
        self._pending.clear()
        self._unknown_chat_refresh_tasks.clear()
        self._pending_unknown_chat_payloads.clear()

    async def send_message(
        self,
        text: str,
        chat_id: Optional[str] = None,
        reply_to_message_id: Optional[str] = None,
        forward_reference: Optional[MaxForwardReference] = None,
        media: tuple[object, ...] = (),
    ) -> dict:
        if not chat_id:
            raise ValueError("Personal MAX backend requires chat_id for sending")

        attaches = await self._outgoing_media_attaches(media)
        # MAX expects outgoing text and attachments inside the nested message object.
        # cid is a client-side id; the authoritative id comes back in the response.
        request_payload = {
            "chatId": int(chat_id),
            "message": {
                "text": text[:4000],
                "cid": int(time.time() * 1000),
                "elements": [],
                "attaches": attaches,
            },
            "notify": True,
        }
        if reply_to_message_id:
            request_payload["message"]["link"] = {
                "type": "REPLY",
                "messageId": str(reply_to_message_id),
            }
        elif forward_reference is not None:
            request_payload["message"]["link"] = {
                "type": "FORWARD",
                "chatId": int(forward_reference.source_chat_id),
                "messageId": str(forward_reference.message_id),
            }
        log.debug(
            "Sending MAX message chat_id=%s reply_to=%s forward=%s attaches=%d link=%s text=%r",
            chat_id,
            reply_to_message_id,
            forward_reference,
            len(attaches),
            request_payload["message"].get("link"),
            text[:500],
        )
        response = await self._send_message_payload_with_attachment_retry(
            request_payload,
            chat_id=chat_id,
            reply_to_message_id=reply_to_message_id,
            attaches=attaches,
        )
        payload = response.get("payload") or {}
        if payload.get("error") == "service.unavailable":
            fallback_attaches = self._audio_attaches_as_files(attaches)
            if fallback_attaches is not None:
                log.warning(
                    "MAX rejected audio attach for chat_id=%s reply_to=%s; retrying as file attach",
                    chat_id,
                    reply_to_message_id,
                )
                fallback_payload = self._copy_message_payload_with_attaches(
                    request_payload,
                    fallback_attaches,
                )
                response = await self._send_message_payload_with_attachment_retry(
                    fallback_payload,
                    chat_id=chat_id,
                    reply_to_message_id=reply_to_message_id,
                    attaches=fallback_attaches,
                )
                payload = response.get("payload") or {}
        log.debug(
            "MAX send response chat_id=%s requested_reply_to=%s response_keys=%s payload_keys=%s response_message=%s",
            chat_id,
            reply_to_message_id,
            sorted(response.keys()),
            sorted(payload.keys()) if isinstance(payload, dict) else [],
            payload.get("message") if isinstance(payload, dict) else None,
        )
        if payload.get("error"):
            log.warning(
                "MAX send rejected chat_id=%s reply_to=%s error=%s attaches=%d",
                chat_id,
                reply_to_message_id,
                payload.get("error"),
                len(attaches),
            )
            raise RuntimeError(f"MAX personal send failed: {payload['error']}")
        return payload

    async def send_button_callback(
        self,
        *,
        chat_id: str,
        callback_id: str,
        payload: str,
        button_type: str = "CALLBACK",
    ) -> dict:
        if not chat_id:
            raise ValueError("Personal MAX backend requires chat_id for button callbacks")
        if not callback_id:
            raise ValueError("MAX button callback requires callbackId")
        if not payload:
            raise ValueError("MAX button callback requires payload")
        request_payload = {
            "callbackId": callback_id,
            "type": (button_type or "CALLBACK").upper(),
            "payload": payload,
            "timestamp": int(time.time() * 1000),
        }
        log.debug(
            "Sending MAX button callback chat_id=%s callback_id_len=%d type=%s",
            chat_id,
            len(callback_id),
            request_payload["type"],
        )
        try:
            response = await self._send_and_wait(self.OP_BUTTON_CALLBACK, request_payload)
        except RuntimeError as exc:
            if "WebSocket is not connected" not in str(exc):
                raise
            log.warning(
                "MAX button callback hit disconnected websocket for chat_id=%s; waiting for reconnect",
                chat_id,
            )
            await self._wait_until_ready(timeout=15)
            response = await self._send_and_wait(self.OP_BUTTON_CALLBACK, request_payload)
        response_payload = response.get("payload") or {}
        if response.get("cmd") != 1 or response_payload.get("error"):
            detail = response_payload.get("error") or response_payload.get("localizedMessage") or "request rejected"
            raise RuntimeError(f"MAX button callback failed: {detail}")
        return response_payload

    async def _send_message_payload_with_attachment_retry(
        self,
        payload: dict,
        *,
        chat_id: str,
        reply_to_message_id: Optional[str],
        attaches: list[dict[str, object]],
    ) -> dict:
        response = await self._send_message_payload(payload, chat_id)
        response_payload = response.get("payload") or {}
        if response_payload.get("error") != "attachment.not.ready":
            return response
        # MAX accepts upload tokens before its media backend can attach them to a message.
        # Retrying the exact same payload preserves the message body and reply target.
        for delay in self.ATTACHMENT_NOT_READY_RETRY_DELAYS:
            log.debug(
                "MAX attachment not ready; retrying send chat_id=%s reply_to=%s delay=%ss attaches=%d",
                chat_id,
                reply_to_message_id,
                delay,
                len(attaches),
            )
            await asyncio.sleep(delay)
            response = await self._send_message_payload(payload, chat_id)
            response_payload = response.get("payload") or {}
            if response_payload.get("error") != "attachment.not.ready":
                return response
        return response

    @staticmethod
    def _audio_attaches_as_files(attaches: list[dict[str, object]]) -> Optional[list[dict[str, object]]]:
        fallback_attaches: list[dict[str, object]] = []
        changed = False
        for attach in attaches:
            if attach.get("_type") == "AUDIO" and attach.get("audioId") is not None:
                fallback_attaches.append({"_type": "FILE", "fileId": attach["audioId"]})
                changed = True
            else:
                fallback_attaches.append(dict(attach))
        return fallback_attaches if changed else None

    @staticmethod
    def _copy_message_payload_with_attaches(payload: dict, attaches: list[dict[str, object]]) -> dict:
        message = dict(payload.get("message") or {})
        message["attaches"] = attaches
        fallback = dict(payload)
        fallback["message"] = message
        return fallback

    async def _send_message_payload(self, payload: dict, chat_id: str) -> dict:
        try:
            return await self._send_and_wait(self.OP_MSG_SEND, payload)
        except RuntimeError as exc:
            if "WebSocket is not connected" not in str(exc):
                raise
            # If reconnect is already underway, wait for readiness and retry once. The
            # caller still owns higher-level error handling if reconnect does not finish.
            log.warning(
                "MAX send hit disconnected websocket for chat_id=%s; waiting for reconnect",
                chat_id,
            )
            await self._wait_until_ready(timeout=15)
            return await self._send_and_wait(self.OP_MSG_SEND, payload)

    async def _outgoing_media_attaches(self, media: tuple[object, ...]) -> list[dict[str, object]]:
        attaches: list[dict[str, object]] = []
        for item in media:
            # XMPP media arrives as lightweight metadata plus URL. Download it locally
            # because MAX upload endpoints require the file bytes.
            upload = await self._download_outgoing_media(item)
            if upload is None:
                continue
            attach_type = self._outgoing_attach_type(upload.mime_type, upload.name)
            if upload.voice:
                # MAX voice messages are AUDIO attaches with Ogg/Opus content, not
                # generic file attaches.
                upload = await self._normalize_outgoing_voice_upload(upload, target="max")
                attach_type = "AUDIO"
            log.debug(
                "Preparing outgoing MAX media name=%r mime=%s size=%s duration=%s voice=%s attach_type=%s expected_voice_mime=%s",
                upload.name,
                upload.mime_type,
                upload.size,
                upload.duration,
                upload.voice,
                attach_type,
                "audio/ogg; codecs=opus",
            )
            if attach_type == "PHOTO":
                attach = await self._upload_outgoing_photo(upload)
            elif attach_type == "VIDEO":
                attach = await self._upload_outgoing_video(upload)
            elif attach_type == "AUDIO":
                attach = await self._upload_outgoing_audio(upload)
            else:
                attach = await self._upload_outgoing_file(upload)
            attaches.append(attach)
        return attaches

    async def _download_outgoing_media(self, media: object) -> Optional[OutgoingMediaUpload]:
        url = str(
            getattr(media, "source_url", None) or getattr(media, "url", "") or ""
        ).strip()
        if not url:
            return None
        mime_type = str(
            getattr(media, "content_type", None)
            or getattr(media, "mime_type", "")
            or "application/octet-stream"
        ).strip().lower()
        name = str(
            getattr(media, "file_name", None) or getattr(media, "name", "") or ""
        ).strip() or self._outgoing_media_name(url, mime_type)
        if self.session is None:
            raise RuntimeError("MAX personal HTTP session is not started")
        timeout = ClientTimeout(total=60)
        # Trust the source response content type over stale XMPP metadata when present.
        async with self.session.get(url, timeout=timeout) as response:
            response.raise_for_status()
            data = await response.read()
            content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type:
            mime_type = content_type
        if not data:
            raise RuntimeError(f"Xabber media download returned empty file: {name}")
        size = len(data)
        return OutgoingMediaUpload(
            data=data,
            name=name,
            mime_type=mime_type,
            size=size,
            width=getattr(media, "width", None),
            height=getattr(media, "height", None),
            duration=getattr(media, "duration", None),
            voice=bool(getattr(media, "voice", False)),
        )

    async def _normalize_outgoing_voice_upload(self, media: OutgoingMediaUpload, *, target: str) -> OutgoingMediaUpload:
        expected_mime = "audio/ogg; codecs=opus"
        if self._is_ogg_opus_voice_upload(media):
            log.debug(
                "Outgoing voice already matches %s format name=%r mime=%s size=%s target=%s",
                expected_mime,
                media.name,
                media.mime_type,
                media.size,
                target,
            )
            return media
        log.debug(
            "Converting outgoing voice for %s old_name=%r old_mime=%s old_size=%s expected_mime=%s",
            target,
            media.name,
            media.mime_type,
            media.size,
            expected_mime,
        )
        return await self._convert_audio_upload(
            media,
            target_name=self._voice_upload_name(media.name),
            target_mime=expected_mime,
            ffmpeg_args=("-vn", "-ac", "1", "-ar", "48000", "-c:a", "libopus", "-b:a", "32k", "-f", "ogg"),
        )

    @staticmethod
    def _is_ogg_opus_voice_upload(media: OutgoingMediaUpload) -> bool:
        mime_type = media.mime_type.lower()
        name = media.name.lower()
        return mime_type.startswith("audio/ogg") and "opus" in mime_type and name.endswith(".ogg")

    @staticmethod
    def _voice_upload_name(name: str) -> str:
        base = os.path.basename(name).rsplit(".", 1)[0] if name else "voice-message"
        return f"{base or 'voice-message'}.ogg"

    async def _convert_audio_upload(
        self,
        media: OutgoingMediaUpload,
        *,
        target_name: str,
        target_mime: str,
        ffmpeg_args: tuple[str, ...],
    ) -> OutgoingMediaUpload:
        if shutil.which("ffmpeg") is None:
            raise RuntimeError("ffmpeg is required to convert voice messages")

        def convert() -> bytes:
            # Run ffmpeg against temp files because it handles more input formats this way
            # than when piping arbitrary media through stdin/stdout.
            with tempfile.TemporaryDirectory(prefix="max-voice-") as tmp_dir:
                input_path = os.path.join(tmp_dir, "input")
                output_path = os.path.join(tmp_dir, target_name)
                with open(input_path, "wb") as file:
                    file.write(media.data)
                command = ("ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-i", input_path, *ffmpeg_args, output_path)
                completed = subprocess.run(command, capture_output=True, check=False)
                if completed.returncode != 0:
                    stderr = completed.stderr.decode("utf-8", errors="replace").strip()
                    raise RuntimeError(f"ffmpeg voice conversion failed: {stderr}")
                with open(output_path, "rb") as file:
                    return file.read()

        data = await asyncio.to_thread(convert)
        if not data:
            raise RuntimeError("ffmpeg voice conversion produced an empty file")
        log.debug(
            "Converted outgoing voice old_name=%r old_mime=%s old_size=%s new_name=%r new_mime=%s new_size=%s",
            media.name,
            media.mime_type,
            media.size,
            target_name,
            target_mime,
            len(data),
        )
        return replace(media, data=data, name=target_name, mime_type=target_mime, size=len(data), voice=True)

    async def _upload_outgoing_photo(self, media: OutgoingMediaUpload) -> dict[str, object]:
        # Uploads are two-step: request a MAX upload slot, upload bytes to that URL,
        # then return the token/id shape expected by OP_MSG_SEND.
        response = await self._send_and_wait(self.OP_PHOTO_UPLOAD, {"count": 1}, timeout=10)
        payload = response.get("payload") or {}
        upload_url = payload.get("url") if isinstance(payload, dict) else None
        if not isinstance(upload_url, str) or not upload_url:
            raise RuntimeError(f"MAX photo upload slot failed: {payload}")
        upload_response = await self._upload_media_multipart(upload_url, media)
        photos = upload_response.get("photos")
        if not isinstance(photos, list) or not photos:
            raise RuntimeError(f"MAX photo upload response has no photos: {upload_response}")
        token = photos[0].get("token") if isinstance(photos[0], dict) else None
        if not isinstance(token, str) or not token:
            raise RuntimeError(f"MAX photo upload response has no token: {upload_response}")
        return {"_type": "PHOTO", "photoToken": token}

    async def _upload_outgoing_video(self, media: OutgoingMediaUpload) -> dict[str, object]:
        # Video uploads return an id/token pair before the video is fully processed.
        # Message send may still need attachment.not.ready retry afterward.
        response = await self._send_and_wait(self.OP_VIDEO_UPLOAD, {"count": 1}, timeout=10)
        payload = response.get("payload") or {}
        info = payload.get("info") if isinstance(payload, dict) else None
        if not isinstance(info, list) or not info:
            raise RuntimeError(f"MAX video upload slot failed: {payload}")
        slot = info[0]
        if not isinstance(slot, dict):
            raise RuntimeError(f"MAX video upload slot malformed: {payload}")
        upload_url = slot.get("url")
        video_id = slot.get("videoId")
        token = slot.get("token")
        if not isinstance(upload_url, str) or video_id is None:
            raise RuntimeError(f"MAX video upload slot has no url/videoId: {payload}")
        await self._upload_media_raw(upload_url, media)
        attach: dict[str, object] = {"_type": "VIDEO", "videoId": video_id}
        if isinstance(token, str) and token:
            attach["token"] = token
        if isinstance(media.duration, int) and media.duration > 0:
            attach["duration"] = media.duration
        return attach

    async def _upload_outgoing_file(self, media: OutgoingMediaUpload) -> dict[str, object]:
        # Generic files use raw upload and are attached by fileId.
        response = await self._send_and_wait(self.OP_FILE_UPLOAD, {"count": 1}, timeout=10)
        payload = response.get("payload") or {}
        info = payload.get("info") if isinstance(payload, dict) else None
        if not isinstance(info, list) or not info:
            raise RuntimeError(f"MAX file upload slot failed: {payload}")
        slot = info[0]
        if not isinstance(slot, dict):
            raise RuntimeError(f"MAX file upload slot malformed: {payload}")
        upload_url = slot.get("url")
        file_id = slot.get("fileId")
        if not isinstance(upload_url, str) or file_id is None:
            raise RuntimeError(f"MAX file upload slot has no url/fileId: {payload}")
        await self._upload_media_raw(upload_url, media)
        return {"_type": "FILE", "fileId": file_id}

    async def _upload_outgoing_audio(self, media: OutgoingMediaUpload) -> dict[str, object]:
        # MAX exposes voice upload through the file upload opcode, but the final attach
        # must be AUDIO/audioId for clients to render it as a voice message.
        response = await self._send_and_wait(self.OP_FILE_UPLOAD, {"count": 1}, timeout=10)
        payload = response.get("payload") or {}
        info = payload.get("info") if isinstance(payload, dict) else None
        if not isinstance(info, list) or not info:
            raise RuntimeError(f"MAX audio upload slot failed: {payload}")
        slot = info[0]
        if not isinstance(slot, dict):
            raise RuntimeError(f"MAX audio upload slot malformed: {payload}")
        upload_url = slot.get("url")
        file_id = slot.get("fileId")
        if not isinstance(upload_url, str) or file_id is None:
            raise RuntimeError(f"MAX audio upload slot has no url/fileId: {payload}")
        await self._upload_media_raw(upload_url, media)
        attach: dict[str, object] = {"_type": "AUDIO", "audioId": file_id}
        if isinstance(media.duration, int) and media.duration > 0:
            attach["duration"] = media.duration * 1000
        log.debug(
            "Built MAX audio attach from upload slot file_id=%s duration_ms=%s name=%r mime=%s size=%s",
            file_id,
            attach.get("duration"),
            media.name,
            media.mime_type,
            media.size,
        )
        return attach

    async def _upload_media_multipart(self, upload_url: str, media: OutgoingMediaUpload) -> dict:
        if self.session is None:
            raise RuntimeError("MAX personal HTTP session is not started")
        form = FormData()
        form.add_field("file", media.data, filename=media.name, content_type=media.mime_type)
        async with self.session.post(upload_url, data=form, timeout=ClientTimeout(total=60)) as response:
            payload = await self._upload_response_payload(response)
        photos = payload.get("photos")
        if isinstance(photos, dict):
            # Some MAX responses return a map keyed by photo id; normalize to the list
            # shape used by the rest of this method.
            payload["photos"] = [
                {"id": photo_id, "token": data.get("token") if isinstance(data, dict) else None}
                for photo_id, data in photos.items()
            ]
        return payload

    async def _upload_media_raw(self, upload_url: str, media: OutgoingMediaUpload) -> dict:
        if self.session is None:
            raise RuntimeError("MAX personal HTTP session is not started")
        headers = {
            "Content-Type": media.mime_type,
            "Content-Disposition": f"attachment; filename={quote(media.name)}",
            "Content-Range": f"0-{media.size - 1}/{media.size}",
        }
        async with self.session.post(
            upload_url,
            data=media.data,
            headers=headers,
            timeout=ClientTimeout(total=120),
        ) as response:
            return await self._upload_response_payload(response)

    @staticmethod
    async def _upload_response_payload(response) -> dict:
        if response.status not in (200, 201):
            reason = response.headers.get("X-Reason") or await response.text()
            raise RuntimeError(f"MAX media upload failed status={response.status}: {reason}")
        text = await response.text()
        if not text.strip():
            return {}
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return {}
        if isinstance(payload, dict) and payload.get("error_code"):
            raise RuntimeError(f"MAX media upload failed: {payload.get('error_code')}")
        return payload if isinstance(payload, dict) else {}

    @staticmethod
    def _outgoing_attach_type(mime_type: str, name: str) -> str:
        if mime_type.startswith("image/"):
            return "PHOTO"
        if mime_type.startswith("video/"):
            return "VIDEO"
        if mime_type.startswith("audio/"):
            # Non-voice audio is safer as FILE. Voice-specific handling happens before
            # this method after _normalize_outgoing_voice_upload().
            return "FILE"
        guessed, _encoding = mimetypes.guess_type(name)
        if guessed:
            return PersonalMaxBackend._outgoing_attach_type(guessed, "")
        return "FILE"

    @staticmethod
    def _outgoing_media_name(url: str, mime_type: str) -> str:
        tail = urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1]
        if tail:
            return tail
        extension = mimetypes.guess_extension(mime_type) or ""
        return f"xabber-media{extension}"

    async def list_contacts(self) -> list[MaxContact]:
        # Contacts are available after the first snapshot has been normalized.
        await asyncio.wait_for(self._contacts_ready.wait(), timeout=20)
        return sorted(self._snapshot_cache.address_book.values(), key=lambda contact: contact.title.casefold())

    async def add_contact_by_phone(self, phone: str) -> MaxContact:
        phone = normalize_phone(phone)
        if not phone:
            raise ValueError("Укажите номер телефона в международном формате.")
        response = await self._send_and_wait(self.OP_CONTACT_ADD_BY_PHONE, {"phone": phone})
        payload = response.get("payload") or {}
        if response.get("cmd") != 1 or payload.get("error"):
            detail = payload.get("error") or payload.get("localizedMessage") or "request rejected"
            raise RuntimeError(f"MAX не смог добавить контакт: {detail}")
        raw_contact = payload.get("contact")
        if not isinstance(raw_contact, dict):
            raise RuntimeError("MAX не вернул добавленный контакт.")
        contact = self._snapshot_cache.max_contact(raw_contact, fallback_title=phone)
        self._snapshot_cache.address_book[contact.contact_id] = contact
        self._snapshot_cache.contact_names[contact.contact_id] = contact.title
        return contact

    def cached_chat(self, chat_id: str) -> Optional[MaxChat]:
        return self._snapshot_cache.chat_by_id(chat_id)

    async def refresh_chat(self, chat_id: str) -> Optional[MaxChat]:
        async with self._chat_refresh_lock:
            # Request enough chats to cover the current cache plus room for newly active
            # dialogs. MAX snapshot pagination is intentionally not modeled here.
            chats_count = max(self.initial_chats_count, len(self._snapshot_cache.chat_titles) + 20)
            log.debug("Refreshing MAX chat metadata for chat_id=%s", chat_id)
            response = await self._send_and_wait(
                self.OP_AUTH_SNAPSHOT,
                {
                    "chatsCount": chats_count,
                    "interactive": False,
                    "token": self.token,
                },
            )
            payload = response.get("payload") or {}
            if response.get("cmd") != 1 or payload.get("error"):
                detail = payload.get("error") or payload.get("localizedMessage") or "request rejected"
                raise RuntimeError(f"MAX chat snapshot refresh rejected: {detail}")
            chats = await self._update_snapshot_cache(payload)
            for chat in chats:
                if chat.chat_id == chat_id:
                    return chat
            return self._snapshot_cache.chat_by_id(chat_id)

    async def fetch_full_group_chat(
        self,
        chat_id: str,
        *,
        page_size: int = 50,
        max_members: int = 5000,
    ) -> Optional[MaxGroupMembersSync]:
        chat = self._snapshot_cache.chat_by_id(chat_id)
        if chat is None:
            return None
        if not chat.is_group:
            return MaxGroupMembersSync(chat=chat)
        previous_members = {member.user_id: member for member in chat.members}
        # Full member sync is requested lazily by the server when it needs the list.
        members = await self._load_chat_members(chat_id, page_size=page_size, max_members=max_members)
        updated = self._snapshot_cache.update_chat_members(chat_id, members)
        if updated is None:
            return MaxGroupMembersSync(chat=chat)
        current_member_ids = {member.user_id for member in members}
        removed_members = tuple(
            previous_members[user_id]
            for user_id in sorted(previous_members.keys() - current_member_ids)
        )
        return MaxGroupMembersSync(chat=updated, removed_members=removed_members)

    async def enrich_group_member_contacts(self, chat_id: str) -> Optional[MaxChat]:
        chat = self._snapshot_cache.chat_by_id(chat_id)
        if chat is None or not chat.is_group:
            return chat
        missing_ids = [
            member.user_id
            for member in chat.members
            if member.title == f"MAX user {member.user_id}"
        ]
        if not missing_ids:
            return chat
        try:
            response = await self._send_and_wait(
                self.OP_CONTACTS_GET,
                {"contactIds": [int(value) if value.isdigit() else value for value in missing_ids]},
                timeout=8,
            )
        except (asyncio.TimeoutError, TimeoutError):
            log.warning("Timed out loading MAX contact names for group chat_id=%s", chat_id)
            return chat
        except Exception:
            log.exception("Failed to load MAX contact names for group chat_id=%s", chat_id)
            return chat
        payload = response.get("payload") or {}
        if response.get("cmd") != 1 or payload.get("error"):
            detail = payload.get("error") or payload.get("localizedMessage") or "request rejected"
            log.warning("MAX group contact name load rejected chat_id=%s: %s", chat_id, detail)
            return chat
        self._snapshot_cache.update_contact_names(payload)
        members = tuple(
            MaxChatMember(
                user_id=member.user_id,
                title=self._snapshot_cache.contact_names.get(member.user_id) or member.title,
                avatar=self._snapshot_cache.member_avatar(member.user_id) or member.avatar,
            )
            for member in chat.members
        )
        updated = self._snapshot_cache.update_chat_members(chat_id, members)
        return updated or chat

    async def _load_chat_members(self, chat_id: str, *, page_size: int = 50, max_members: int = 5000) -> tuple[MaxChatMember, ...]:
        marker: Optional[object] = None
        member_ids: list[str] = []
        seen_ids: set[str] = set()
        while marker is not None or not member_ids:
            # MAX uses marker pagination for group members. The first request has no
            # marker; subsequent requests reuse the marker from the previous response.
            payload = {
                "type": "MEMBER",
                "chatId": int(chat_id),
                "count": page_size,
            }
            if marker is not None:
                payload["marker"] = marker
            response = await self._send_and_wait(self.OP_CHAT_MEMBERS, payload)
            response_payload = response.get("payload") or {}
            if response.get("cmd") != 1 or response_payload.get("error"):
                detail = response_payload.get("error") or response_payload.get("localizedMessage") or "request rejected"
                raise RuntimeError(f"MAX chat members load rejected: {detail}")
            raw_members = response_payload.get("members") or []
            if not isinstance(raw_members, list):
                break
            contacts_payload = {"contacts": []}
            for item in raw_members:
                if not isinstance(item, dict):
                    continue
                contact = item.get("contact")
                if isinstance(contact, dict):
                    # Member rows can carry embedded contacts. Feed them into the normal
                    # contact-name cache instead of maintaining a second name source.
                    contacts_payload["contacts"].append(contact)
                contact_id = None
                if isinstance(contact, dict) and contact.get("id") is not None:
                    contact_id = str(contact["id"])
                elif item.get("id") is not None:
                    contact_id = str(item["id"])
                if not contact_id or contact_id == self.my_id or contact_id in seen_ids:
                    continue
                seen_ids.add(contact_id)
                member_ids.append(contact_id)
                if len(member_ids) >= max_members:
                    break
            if contacts_payload["contacts"]:
                self._snapshot_cache.update_contact_names(contacts_payload)
            marker = response_payload.get("marker")
            if len(member_ids) >= max_members:
                break
            if marker is None:
                break
        members = tuple(
            MaxChatMember(
                user_id=member_id,
                title=self._snapshot_cache.contact_names.get(member_id) or f"MAX user {member_id}",
                avatar=self._snapshot_cache.member_avatar(member_id),
            )
            for member_id in member_ids
        )
        log.debug("Loaded MAX chat members via opcode 59 chat_id=%s count=%d", chat_id, len(members))
        return members

    async def _run_forever(self) -> None:
        while not self._closed.is_set():
            try:
                await self._connect_once()
            except asyncio.CancelledError:
                raise
            except MaxAuthorizationError as exc:
                if not self._ready.is_set() and not self._startup_failed.is_set():
                    self._startup_exception = exc
                    self._startup_failed.set()
                    log.error("MAX personal backend startup failed: %s", exc)
                elif exc.terminal:
                    self._closed.set()
                    self._schedule_authorization_lost(exc)
                    log.warning("MAX personal backend authorization lost: %s", exc)
                else:
                    log.exception("MAX personal backend connection failed")
            except Exception as exc:
                if not self._ready.is_set() and not self._startup_failed.is_set():
                    self._startup_exception = exc
                    self._startup_failed.set()
                    log.error("MAX personal backend startup failed: %s", exc)
                else:
                    log.exception("MAX personal backend connection failed")
            finally:
                self._ready.clear()
                # A dropped websocket invalidates all request futures tied to sequence ids.
                if self._heartbeat_task is not None:
                    self._heartbeat_task.cancel()
                    self._heartbeat_task = None
                if self._snapshot_task is not None:
                    self._snapshot_task.cancel()
                    self._snapshot_task = None
                self.ws = None
                for future in self._pending.values():
                    if not future.done():
                        future.cancel()
                self._pending.clear()

            if not self._closed.is_set():
                # Keep reconnect simple and predictable; caller-facing start() has already
                # completed after the first successful connection.
                await asyncio.sleep(self.reconnect_delay)

    async def _connect_once(self) -> None:
        if self.session is None:
            raise RuntimeError("MAX personal backend session is not started")

        self.ws = await self.session.ws_connect(
            "wss://ws-api.oneme.ru/websocket",
            headers=web_client_headers(),
        )
        self._seq = 0
        await self._send_json(self.OP_HANDSHAKE, web_device_handshake(self.device_id, self.app_version))

        async for msg in self.ws:
            if msg.type == WSMsgType.TEXT:
                # All MAX protocol messages share one websocket stream. _handle_frame
                # separates direct responses from async dispatch events.
                await self._handle_frame(json.loads(msg.data))
            elif msg.type in (WSMsgType.CLOSED, WSMsgType.ERROR):
                break

    async def _handle_frame(self, data: dict) -> None:
        seq = data.get("seq")
        if isinstance(seq, int):
            future = self._pending.pop(seq, None)
            if future is not None and not future.done():
                # Frames with seq are responses to _send_and_wait requests.
                future.set_result(data)
                return

        opcode = data.get("opcode")
        cmd = data.get("cmd")
        payload = data.get("payload") or {}
        if opcode == self.OP_HANDSHAKE and cmd == 1:
            log.info("MAX personal handshake OK; authorizing")
            # Authorization returns a snapshot that seeds contacts/chats before live
            # dispatches are processed.
            await self._send_json(
                self.OP_AUTH_SNAPSHOT,
                {
                    "chatsCount": self.initial_chats_count,
                    "interactive": True,
                    "token": self.token,
                },
            )
        elif opcode == self.OP_AUTH_SNAPSHOT and cmd == 1:
            self.my_id = self._extract_profile_id(payload)
            self._snapshot_cache.set_profile_id(self.my_id)
            self._contacts_ready.clear()
            log.info("MAX personal authorized as ID %s", self.my_id)
            self._ready.set()
            # Snapshot normalization can be slower than marking the socket ready. Run it
            # in the background so reconnect/startup is not blocked on roster sync.
            self._heartbeat_task = asyncio.create_task(self._heartbeat())
            self._snapshot_task = asyncio.create_task(self._synchronize_snapshot_chats(payload))
        elif opcode == self.OP_AUTH_SNAPSHOT:
            detail = payload.get("error") or payload.get("localizedMessage")
            suffix = f" ({detail})" if isinstance(detail, str) and detail else ""
            raise MaxAuthorizationError(
                "MAX personal authorization snapshot was rejected"
                f"{suffix}; send /login to authorize MAX again.",
                terminal=detail == "login.token",
            )
        elif opcode == self.OP_DISPATCH:
            await self._dispatch_message(payload)

    async def _dispatch_message(self, payload: dict) -> None:
        # Dispatch payloads may include chat metadata updates and/or a message.
        await self._update_chat_from_dispatch(payload)
        if self._message_handler is None:
            return
        message = payload.get("message") or {}
        content_message, content_source = self._dispatch_content_message(message)
        text = self._dispatch_text(message, content_message)
        media = self._snapshot_cache.extract_media(content_message)
        buttons = self._extract_inline_keyboard_buttons(message)
        # First pass extracts media URLs already present in the payload. The unsupported
        # lists capture attachments that need extra MAX API calls to obtain URLs.
        video_attachments = self._snapshot_cache.unsupported_video_attachments(content_message)
        file_attachments = self._snapshot_cache.unsupported_file_attachments(content_message)
        audio_attachments = self._snapshot_cache.unsupported_audio_attachments(content_message)
        sender_id = message.get("sender")
        if sender_id is None:
            return
        link_type = self._link_type(message)
        if content_source != "message":
            log.debug(
                "MAX dispatch uses forwarded content chat_id=%s message_id=%s linked_message_id=%s link_type=%s media=%d unsupported_video=%d unsupported_file=%d unsupported_audio=%d linked_keys=%s",
                payload.get("chatId"),
                message.get("id"),
                content_message.get("id"),
                link_type,
                len(media),
                len(video_attachments),
                len(file_attachments),
                len(audio_attachments),
                sorted(content_message.keys()),
            )
        if content_message.get("attaches") or content_message.get("attachments"):
            log.debug(
                "MAX media dispatch chat_id=%s message_id=%s extracted=%d unsupported_video=%d unsupported_file=%d unsupported_audio=%d",
                payload.get("chatId"),
                message.get("id"),
                len(media),
                len(video_attachments),
                len(file_attachments),
                len(audio_attachments),
            )
        if not text and not media and not buttons and not video_attachments and not file_attachments and not audio_attachments:
            if content_message.get("attaches") or content_message.get("attachments"):
                log.debug("MAX dispatch message has unsupported attachments")
                self._schedule_unsupported_media_probe(payload, content_message, stage="dispatch")
            elif link_type:
                log.debug(
                    "MAX dispatch message has no deliverable content chat_id=%s message_id=%s link_type=%s message_keys=%s linked_keys=%s",
                    payload.get("chatId"),
                    message.get("id"),
                    link_type,
                    sorted(message.keys()),
                    sorted(content_message.keys()) if content_source != "message" else [],
                )
            return
        chat_id = str(payload["chatId"]) if payload.get("chatId") is not None else None
        if chat_id is not None and not self._snapshot_cache.has_chat(chat_id):
            # Delay delivery until a snapshot refresh can provide title/group metadata.
            self._queue_unknown_chat_message(chat_id, payload)
            return

        if video_attachments or file_attachments or audio_attachments:
            # Resolve media sources asynchronously so the websocket receive loop keeps
            # reading new frames while extra API requests run.
            log.debug(
                "MAX dispatch message has attachments requiring source resolution chat_id=%s message_id=%s videos=%d files=%d audios=%d",
                chat_id,
                message.get("id"),
                len(video_attachments),
                len(file_attachments),
                len(audio_attachments),
            )
            self._schedule_dispatch_payload_delivery(payload, reason="media-source-resolution")
            return

        await self._deliver_dispatch_payload(payload)

    def _is_duplicate_message(self, event: MaxIncomingMessage) -> bool:
        return self._deduplicator.is_duplicate(event)

    async def _deliver_dispatch_payload(self, payload: dict) -> None:
        if self._message_handler is None:
            return
        message = payload.get("message") or {}
        content_message, content_source = self._dispatch_content_message(message)
        text = self._dispatch_text(message, content_message)
        # Deferred delivery runs the full resolver, including ids-only audio/video/file
        # attachments that were detected in _dispatch_message().
        media = await self._message_media(payload, content_message, display_message_id=message.get("id"))
        buttons = self._extract_inline_keyboard_buttons(message)
        sender_id = message.get("sender")
        if sender_id is None:
            return
        if buttons:
            log.debug(
                "MAX inline keyboard extracted chat_id=%s message_id=%s rows=%d",
                payload.get("chatId"),
                message.get("id"),
                len(buttons),
            )
        if content_source != "message":
            log.debug(
                "MAX deferred dispatch uses forwarded content chat_id=%s message_id=%s linked_message_id=%s link_type=%s resolved=%d",
                payload.get("chatId"),
                message.get("id"),
                content_message.get("id"),
                self._link_type(message),
                len(media),
            )
        if content_message.get("attaches") or content_message.get("attachments"):
            log.debug(
                "MAX media deferred chat_id=%s message_id=%s resolved=%d",
                payload.get("chatId"),
                message.get("id"),
                len(media),
            )
        if not text and not media and not buttons:
            if content_message.get("attaches") or content_message.get("attachments"):
                log.debug("MAX deferred dispatch message has unsupported attachments")
                self._schedule_unsupported_media_probe(payload, content_message, stage="deferred")
            return
        reply_to_message_id = self._extract_reply_to_message_id(message)
        event = MaxIncomingMessage(
            sender_id=str(sender_id),
            text=text,
            chat_id=str(payload["chatId"]) if payload.get("chatId") is not None else None,
            chat_title=self._snapshot_cache.message_chat_title(payload, sender_id),
            sender_title=self._snapshot_cache.contact_names.get(str(sender_id)),
            message_id=str(message["id"]) if message.get("id") is not None else None,
            reply_to_message_id=reply_to_message_id,
            is_self=self.my_id is not None and str(sender_id) == str(self.my_id),
            is_group=self._snapshot_cache.message_is_group(payload),
            media=media,
            buttons=buttons,
            raw=payload,
        )
        if event.is_group:
            log.debug(
                "MAX dispatch group message chat_id=%s message_id=%s sender=%s self=%s reply_to=%s link=%s message_keys=%s",
                event.chat_id,
                event.message_id,
                event.sender_id,
                event.is_self,
                event.reply_to_message_id,
                message.get("link"),
                sorted(message.keys()),
            )
        elif event.reply_to_message_id or message.get("link"):
            log.debug(
                "MAX dispatch direct message chat_id=%s message_id=%s sender=%s self=%s reply_to=%s link=%s message_keys=%s",
                event.chat_id,
                event.message_id,
                event.sender_id,
                event.is_self,
                event.reply_to_message_id,
                message.get("link"),
                sorted(message.keys()),
            )
        if self._is_duplicate_message(event):
            # MAX can resend live events around reconnects. Dedup by chat/message id so
            # Xabber archive does not receive duplicates.
            log.debug(
                "Skipping duplicate MAX message chat_id=%s message_id=%s",
                event.chat_id,
                event.message_id,
            )
            return
        await self._message_handler(event)

    def _schedule_dispatch_payload_delivery(self, payload: dict, *, reason: str) -> None:
        # Fire-and-log task keeps heavy media resolution outside the websocket frame
        # handler while preserving failure visibility.
        task = asyncio.create_task(self._deliver_dispatch_payload(payload))
        task.add_done_callback(lambda done: self._log_dispatch_delivery_task_failure(done, reason))

    @staticmethod
    def _log_dispatch_delivery_task_failure(task: asyncio.Task, reason: str) -> None:
        try:
            task.result()
        except asyncio.CancelledError:
            pass
        except Exception:
            log.exception("MAX deferred dispatch delivery task failed reason=%s", reason)

    def _schedule_unsupported_media_probe(self, payload: dict, message: dict, *, stage: str) -> None:
        # Diagnostic probe is intentionally best-effort; it helps learn new MAX payload
        # shapes without blocking normal text delivery.
        task = asyncio.create_task(self._diagnose_unsupported_media(payload, message, stage=stage))
        task.add_done_callback(self._log_media_probe_task_failure)

    @staticmethod
    def _log_media_probe_task_failure(task: asyncio.Task) -> None:
        try:
            task.result()
        except asyncio.CancelledError:
            pass
        except Exception:
            log.exception("MAX video source probe task failed")

    async def _diagnose_unsupported_media(self, payload: dict, message: dict, *, stage: str) -> None:
        chat_id = payload.get("chatId")
        message_id = message.get("id")
        attachments = self._snapshot_cache.unsupported_video_attachments(message)
        if chat_id is None or message_id is None or not attachments:
            log.debug(
                "MAX video source probe skipped stage=%s chat_id=%s message_id=%s video_attachments=%d",
                stage,
                chat_id,
                message_id,
                len(attachments),
            )
            return
        for attach in attachments[:3]:
            video_id = attach.get("videoId")
            token = attach.get("token")
            if video_id is None:
                continue
            request = {
                "videoId": video_id,
                "token": token if isinstance(token, str) else "",
                "chatId": chat_id,
                "messageId": message_id,
            }
            try:
                response = await self._send_and_wait(self.OP_VIDEO_SOURCES, request, timeout=10)
            except Exception as exc:
                log.debug(
                    "MAX video source probe failed stage=%s chat_id=%s message_id=%s video_id=%s token_present=%s error=%s",
                    stage,
                    chat_id,
                    message_id,
                    video_id,
                    bool(token),
                    exc,
                )
                continue
            response_payload = response.get("payload") or {}
            log.debug(
                "MAX video source probe result stage=%s chat_id=%s message_id=%s video_id=%s token_present=%s cmd=%s opcode=%s payload_keys=%s sources=%s error=%s",
                stage,
                chat_id,
                message_id,
                video_id,
                bool(token),
                response.get("cmd"),
                response.get("opcode"),
                sorted(response_payload.keys()) if isinstance(response_payload, dict) else type(response_payload).__name__,
                self._safe_video_sources(response_payload),
                response_payload.get("error") if isinstance(response_payload, dict) else None,
            )

    @staticmethod
    def _safe_video_sources(payload: object) -> list[dict[str, object]]:
        if not isinstance(payload, dict):
            return []
        sources = []
        for key, value in sorted(payload.items()):
            if not isinstance(key, str) or not key.startswith("MP4_") or not isinstance(value, str):
                continue
            parsed = urlsplit(value)
            # Log only URL shape, not full signed CDN URLs.
            sources.append(
                {
                    "quality": key,
                    "scheme": parsed.scheme,
                    "host": parsed.netloc,
                    "path_tail": parsed.path.rsplit("/", 1)[-1],
                    "query_keys": sorted(
                        name
                        for name in {part.split("=", 1)[0] for part in parsed.query.split("&") if part}
                        if name
                    ),
                }
            )
        return sources

    async def _message_media(
        self,
        payload: dict,
        message: dict,
        *,
        display_message_id: object = None,
    ) -> tuple[MaxMedia, ...]:
        # Some dispatches already contain direct CDN URLs, while voice/video/file
        # attachments often contain only ids. Resolve both forms into one media list.
        resolved = list(self._snapshot_cache.extract_media(message))
        resolved.extend(await self._resolve_audio_attachment_media(payload, message))
        resolved.extend(await self._resolve_video_attachment_media(payload, message))
        resolved.extend(await self._resolve_file_attachment_media(payload, message))
        resolved_media = await self._resolve_media_mime_types(tuple(resolved))
        return self._normalize_inbound_image_names(resolved_media, payload, message, display_message_id=display_message_id)

    @classmethod
    def _normalize_inbound_image_names(
        cls,
        media: tuple[MaxMedia, ...],
        payload: dict,
        message: dict,
        *,
        display_message_id: object = None,
    ) -> tuple[MaxMedia, ...]:
        chat_id = payload.get("chatId")
        message_id = display_message_id if display_message_id is not None else message.get("id")
        if chat_id is None or message_id is None:
            return media
        normalized: list[MaxMedia] = []
        image_index = 0
        for item in media:
            if not cls._is_inbound_image_media(item):
                normalized.append(item)
                continue
            image_index += 1
            suffix = "" if image_index == 1 else f"-{image_index}"
            normalized.append(replace(item, name=f"image-{chat_id}-{message_id}{suffix}.webp"))
        return tuple(normalized)

    @staticmethod
    def _is_inbound_image_media(media: MaxMedia) -> bool:
        mime_type = (media.mime_type or "").lower()
        if mime_type.startswith("image/"):
            return True
        guessed, _encoding = mimetypes.guess_type((media.url or "").split("?", 1)[0])
        return bool(guessed and guessed.startswith("image/"))

    @classmethod
    def _dispatch_content_message(cls, message: dict) -> tuple[dict, str]:
        linked_message = cls._forwarded_link_message(message)
        if linked_message is not None and not cls._message_has_media_content(message):
            return linked_message, "forward"
        return message, "message"

    @staticmethod
    def _message_has_media_content(message: dict) -> bool:
        return bool(message.get("attaches") or message.get("attachments"))

    @classmethod
    def _forwarded_link_message(cls, message: dict) -> Optional[dict]:
        if cls._link_type(message) != "FORWARD":
            return None
        link = message.get("link") or {}
        if not isinstance(link, dict):
            return None
        linked_message = link.get("message") or {}
        return linked_message if isinstance(linked_message, dict) else None

    @staticmethod
    def _link_type(message: dict) -> str:
        link = message.get("link") or {}
        if not isinstance(link, dict):
            return ""
        return str(link.get("type") or "").upper()

    @staticmethod
    def _dispatch_text(message: dict, content_message: dict) -> str:
        text = str(message.get("text") or "").strip()
        if text:
            return text
        return str(content_message.get("text") or "").strip()

    @classmethod
    def _extract_inline_keyboard_buttons(cls, message: dict) -> tuple[tuple[MaxButton, ...], ...]:
        attachments = []
        for key in ("attaches", "attachments"):
            value = message.get(key)
            if isinstance(value, list):
                attachments.extend(item for item in value if isinstance(item, dict))
            elif isinstance(value, dict):
                attachments.append(value)

        rows: list[tuple[MaxButton, ...]] = []
        for attachment in attachments:
            if not cls._is_inline_keyboard_attachment(attachment):
                continue
            callback_id = cls._extract_keyboard_callback_id(attachment)
            for row in cls._extract_keyboard_rows(attachment):
                buttons = tuple(
                    button
                    for item in row
                    if (button := cls._extract_keyboard_button(item, callback_id=callback_id)) is not None
                )
                if buttons:
                    rows.append(buttons)
        return tuple(rows)

    @staticmethod
    def _extract_keyboard_callback_id(attachment: dict) -> Optional[str]:
        for source in (attachment, attachment.get("keyboard")):
            if not isinstance(source, dict):
                continue
            for key in ("callbackId", "callback_id", "callbackID"):
                value = source.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        return None

    @staticmethod
    def _is_inline_keyboard_attachment(attachment: dict) -> bool:
        for key in ("type", "_type", "attachType", "attachmentType"):
            value = attachment.get(key)
            if isinstance(value, str) and value.upper() == "INLINE_KEYBOARD":
                return True
        return False

    @classmethod
    def _extract_keyboard_rows(cls, attachment: dict) -> tuple[tuple[object, ...], ...]:
        keyboard = attachment.get("keyboard")
        if isinstance(keyboard, dict):
            return cls._extract_keyboard_rows(keyboard)
        if isinstance(keyboard, list):
            return cls._normalize_keyboard_rows(keyboard)
        parallel_rows = cls._parallel_keyboard_rows(attachment)
        if parallel_rows:
            return parallel_rows
        for key in ("buttons", "rows", "keyboard"):
            rows = attachment.get(key)
            if isinstance(rows, list):
                payload_rows = attachment.get("payloads")
                return cls._normalize_keyboard_rows(rows, payload_rows if isinstance(payload_rows, list) else None)
        return ()

    @classmethod
    def _normalize_keyboard_rows(cls, rows: list, payload_rows: Optional[list] = None) -> tuple[tuple[object, ...], ...]:
        normalized: list[tuple[object, ...]] = []
        for row_idx, row in enumerate(rows):
            if isinstance(row, dict):
                parallel_row = cls._parallel_keyboard_row(row)
                if parallel_row:
                    normalized.append(parallel_row)
                    continue
                nested = row.get("buttons") or row.get("items") or row.get("row")
                if isinstance(nested, list):
                    normalized.append(tuple(nested))
                else:
                    normalized.append((row,))
            elif isinstance(row, list):
                payload_row = payload_rows[row_idx] if payload_rows and row_idx < len(payload_rows) else None
                if isinstance(payload_row, list) and all(isinstance(item, str) for item in row):
                    normalized.append(
                        tuple(
                            {"text": text, "payload": payload}
                            for text, payload in zip(row, payload_row)
                        )
                    )
                else:
                    normalized.append(tuple(row))
        return tuple(normalized)

    @classmethod
    def _parallel_keyboard_rows(cls, attachment: dict) -> tuple[tuple[object, ...], ...]:
        texts = attachment.get("texts")
        payloads = attachment.get("payloads")
        if not isinstance(texts, list) or not isinstance(payloads, list):
            return ()
        return cls._normalize_keyboard_rows(texts, payloads)

    @staticmethod
    def _parallel_keyboard_row(row: dict) -> tuple[object, ...]:
        texts = row.get("texts")
        payloads = row.get("payloads")
        if not isinstance(texts, list) or not isinstance(payloads, list):
            return ()
        return tuple(
            {"text": text, "payload": payload}
            for text, payload in zip(texts, payloads)
        )

    @staticmethod
    def _extract_keyboard_button(item: object, *, callback_id: Optional[str]) -> Optional[MaxButton]:
        if isinstance(item, str) and item.strip():
            return MaxButton(text=item.strip(), payload=item.strip(), callback_id=callback_id)
        if not isinstance(item, dict):
            return None
        text = item.get("text") or item.get("label") or item.get("title")
        payload = item.get("payload") or item.get("callback") or item.get("callbackData") or item.get("data")
        button_type = item.get("type") or item.get("_type") or "CALLBACK"
        if payload is None and isinstance(item.get("intent"), str):
            payload = item.get("intent")
        if payload is None and isinstance(item.get("id"), str):
            payload = item.get("id")
        if not isinstance(text, str) or not text.strip():
            return None
        if payload is None:
            payload = text
        return MaxButton(
            text=text.strip(),
            payload=str(payload),
            callback_id=callback_id,
            kind=str(button_type or "CALLBACK"),
        )

    async def _resolve_audio_attachment_media(self, payload: dict, message: dict) -> tuple[MaxMedia, ...]:
        chat_id = payload.get("chatId")
        message_id = message.get("id")
        if chat_id is None or message_id is None:
            return ()
        result: list[MaxMedia] = []
        for attach in self._snapshot_cache.unsupported_audio_attachments(message):
            media_id_key, media_id = self._audio_attachment_id(attach)
            if media_id is None:
                continue
            # Voice/audio attachments often need OP_FILE_DOWNLOAD before Xabber can see
            # a usable media URL.
            response_payload = await self._fetch_audio_download(
                media_id=media_id,
                media_id_key=media_id_key,
                chat_id=chat_id,
                message_id=message_id,
            )
            source_url = response_payload.get("url") if isinstance(response_payload, dict) else None
            if not isinstance(source_url, str) or not source_url.strip():
                log.debug(
                    "MAX audio download response has no URL chat_id=%s message_id=%s %s=%s payload_keys=%s error=%s",
                    chat_id,
                    message_id,
                    media_id_key,
                    media_id,
                    sorted(response_payload.keys()) if isinstance(response_payload, dict) else type(response_payload).__name__,
                    response_payload.get("error") if isinstance(response_payload, dict) else None,
                )
                continue
            name = self._audio_media_name(attach, media_id)
            result.append(
                MaxMedia(
                    url=source_url.strip(),
                    name=name,
                    mime_type=self._audio_media_mime_type(attach, name, source_url),
                    size=self._snapshot_cache._extract_media_size(attach),
                    duration=self._snapshot_cache._extract_media_duration(attach),
                    voice=True,
                )
            )
            log.debug(
                "Resolved MAX voice/audio media chat_id=%s message_id=%s %s=%s name=%r mime=%s duration=%s expected_xabber_voice_mime=%s voice=%s",
                chat_id,
                message_id,
                media_id_key,
                media_id,
                name,
                result[-1].mime_type,
                result[-1].duration,
                "audio/ogg; codecs=opus",
                result[-1].voice,
            )
        return tuple(result)

    async def _fetch_audio_download(
        self,
        *,
        media_id: object,
        media_id_key: str,
        chat_id: object,
        message_id: object,
    ) -> dict:
        request = {
            "fileId": media_id,
            "chatId": chat_id,
            "messageId": message_id,
        }
        if media_id_key != "fileId":
            request[media_id_key] = media_id
        response = await self._send_and_wait(self.OP_FILE_DOWNLOAD, request, timeout=10)
        response_payload = response.get("payload") or {}
        if response.get("cmd") != 1 or not isinstance(response_payload, dict):
            return response_payload if isinstance(response_payload, dict) else {}
        return response_payload

    @staticmethod
    def _audio_attachment_id(attach: dict) -> tuple[str, Optional[object]]:
        for key in ("audioId", "voiceId", "fileId"):
            value = attach.get(key)
            if value is not None:
                return key, value
        return "fileId", None

    @staticmethod
    def _audio_media_name(attach: dict, media_id: object) -> str:
        for key in ("name", "fileName", "file_name", "filename", "title"):
            value = attach.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return f"MAX voice {media_id}.ogg"

    @staticmethod
    def _audio_media_mime_type(attach: dict, name: str, url: str) -> str:
        explicit = MaxSnapshotCache._extract_media_mime_type(attach, url)
        if explicit != "application/octet-stream":
            return explicit
        guessed, _encoding = mimetypes.guess_type(name)
        if guessed:
            return guessed
        guessed, _encoding = mimetypes.guess_type(url.split("?", 1)[0])
        return guessed or "audio/ogg"

    async def _resolve_video_attachment_media(self, payload: dict, message: dict) -> tuple[MaxMedia, ...]:
        chat_id = payload.get("chatId")
        message_id = message.get("id")
        if chat_id is None or message_id is None:
            return ()
        result: list[MaxMedia] = []
        for attach in self._snapshot_cache.unsupported_video_attachments(message):
            video_id = attach.get("videoId")
            if video_id is None:
                continue
            # Video payloads frequently carry only videoId/token. Ask MAX for concrete
            # MP4 sources and choose the best quality below.
            response_payload = await self._fetch_video_sources(
                video_id=video_id,
                token=attach.get("token"),
                chat_id=chat_id,
                message_id=message_id,
            )
            source_url = self._best_video_source_url(response_payload)
            if not source_url:
                log.debug(
                    "MAX video source response has no MP4 source chat_id=%s message_id=%s video_id=%s payload_keys=%s error=%s",
                    chat_id,
                    message_id,
                    video_id,
                    sorted(response_payload.keys()) if isinstance(response_payload, dict) else type(response_payload).__name__,
                    response_payload.get("error") if isinstance(response_payload, dict) else None,
                )
                continue
            result.append(
                MaxMedia(
                    url=source_url,
                    name=self._video_media_name(attach, video_id),
                    mime_type="video/mp4",
                    thumbnail_url=self._snapshot_cache._extract_media_thumbnail_url(attach),
                    width=self._snapshot_cache._extract_media_int(attach, ("width", "w")),
                    height=self._snapshot_cache._extract_media_int(attach, ("height", "h")),
                    duration=self._snapshot_cache._extract_media_duration(attach),
                )
            )
        return tuple(result)

    async def _fetch_video_sources(
        self,
        *,
        video_id: object,
        token: object,
        chat_id: object,
        message_id: object,
    ) -> dict:
        request = {
            "videoId": video_id,
            "token": token if isinstance(token, str) else "",
            "chatId": chat_id,
            "messageId": message_id,
        }
        response = await self._send_and_wait(self.OP_VIDEO_SOURCES, request, timeout=10)
        response_payload = response.get("payload") or {}
        if response.get("cmd") != 1 or not isinstance(response_payload, dict):
            return response_payload if isinstance(response_payload, dict) else {}
        return response_payload

    @staticmethod
    def _best_video_source_url(payload: dict) -> Optional[str]:
        candidates: list[tuple[int, str]] = []
        for key, value in payload.items():
            if not isinstance(key, str) or not key.startswith("MP4_") or not isinstance(value, str):
                continue
            quality = key.removeprefix("MP4_")
            rank = int(quality) if quality.isdigit() else 0
            candidates.append((rank, value))
        if not candidates:
            return None
        # Prefer the highest numeric MP4_* variant so Xabber gets the best direct file.
        return max(candidates, key=lambda item: item[0])[1]

    @staticmethod
    def _video_media_name(attach: dict, video_id: object) -> str:
        for key in ("name", "fileName", "file_name", "filename", "title"):
            value = attach.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return f"MAX video {video_id}.mp4"

    async def _resolve_file_attachment_media(self, payload: dict, message: dict) -> tuple[MaxMedia, ...]:
        chat_id = payload.get("chatId")
        message_id = message.get("id")
        if chat_id is None or message_id is None:
            return ()
        result: list[MaxMedia] = []
        for attach in self._snapshot_cache.unsupported_file_attachments(message):
            file_id = attach.get("fileId")
            if file_id is None:
                continue
            # File attachments also need a download URL lookup before they can be
            # represented as XMPP file-sharing media.
            response_payload = await self._fetch_file_download(
                file_id=file_id,
                chat_id=chat_id,
                message_id=message_id,
            )
            source_url = response_payload.get("url") if isinstance(response_payload, dict) else None
            if not isinstance(source_url, str) or not source_url.strip():
                log.debug(
                    "MAX file download response has no URL chat_id=%s message_id=%s file_id=%s payload_keys=%s error=%s",
                    chat_id,
                    message_id,
                    file_id,
                    sorted(response_payload.keys()) if isinstance(response_payload, dict) else type(response_payload).__name__,
                    response_payload.get("error") if isinstance(response_payload, dict) else None,
                )
                continue
            if response_payload.get("unsafe"):
                log.debug(
                    "MAX file download response marked unsafe chat_id=%s message_id=%s file_id=%s name=%r",
                    chat_id,
                    message_id,
                    file_id,
                    attach.get("name"),
                )
            name = self._file_media_name(attach, file_id)
            result.append(
                MaxMedia(
                    url=source_url.strip(),
                    name=name,
                    mime_type=self._file_media_mime_type(name, source_url),
                    size=self._snapshot_cache._extract_media_size(attach),
                    thumbnail_url=self._snapshot_cache._extract_media_thumbnail_url(attach),
                )
            )
        return tuple(result)

    async def _fetch_file_download(
        self,
        *,
        file_id: object,
        chat_id: object,
        message_id: object,
    ) -> dict:
        response = await self._send_and_wait(
            self.OP_FILE_DOWNLOAD,
            {
                "fileId": file_id,
                "chatId": chat_id,
                "messageId": message_id,
            },
            timeout=10,
        )
        response_payload = response.get("payload") or {}
        if response.get("cmd") != 1 or not isinstance(response_payload, dict):
            return response_payload if isinstance(response_payload, dict) else {}
        return response_payload

    @staticmethod
    def _file_media_name(attach: dict, file_id: object) -> str:
        for key in ("name", "fileName", "file_name", "filename", "title"):
            value = attach.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return f"MAX file {file_id}"

    @staticmethod
    def _file_media_mime_type(name: str, url: str) -> str:
        guessed, _encoding = mimetypes.guess_type(name)
        if guessed:
            return PersonalMaxBackend._download_file_mime_type(guessed)
        guessed, _encoding = mimetypes.guess_type(url.split("?", 1)[0])
        if guessed:
            return PersonalMaxBackend._download_file_mime_type(guessed)
        return "application/octet-stream"

    @staticmethod
    def _download_file_mime_type(mime_type: str) -> str:
        top_level = mime_type.split("/", 1)[0].lower()
        if top_level in {"video", "audio", "image"}:
            # Files sent as FILE should stay generic; otherwise clients may render them
            # as media previews and bypass the intended MAX attachment type.
            return "application/octet-stream"
        return mime_type

    async def _resolve_media_mime_types(self, media: tuple[MaxMedia, ...]) -> tuple[MaxMedia, ...]:
        if not media:
            return media
        resolved: list[MaxMedia] = []
        for item in media:
            if item.mime_type != "application/octet-stream":
                resolved.append(item)
                continue
            # Some MAX URLs lack filename extensions. Probe headers to improve XMPP
            # rendering, but keep the item if probing fails.
            content_type = await self._media_content_type(item.url)
            if content_type:
                log.debug(
                    "Resolved MAX media content type url=%s old_mime=%s new_mime=%s name=%s size=%s width=%s height=%s",
                    item.url,
                    item.mime_type,
                    content_type,
                    item.name,
                    item.size,
                    item.width,
                    item.height,
                )
                resolved.append(replace(item, mime_type=content_type))
            else:
                log.debug(
                    "Could not resolve MAX media content type url=%s mime=%s name=%s size=%s width=%s height=%s",
                    item.url,
                    item.mime_type,
                    item.name,
                    item.size,
                    item.width,
                    item.height,
                )
                resolved.append(item)
        return tuple(resolved)

    async def _media_content_type(self, url: str) -> Optional[str]:
        if self.session is None:
            return None
        timeout = ClientTimeout(total=5)
        for method in ("HEAD", "GET"):
            try:
                if method == "HEAD":
                    response_context = self.session.head(url, allow_redirects=True, timeout=timeout)
                else:
                    # Some CDNs do not support HEAD correctly. A ranged GET reads only
                    # the first byte but still exposes Content-Type.
                    response_context = self.session.get(
                        url,
                        allow_redirects=True,
                        headers={"Range": "bytes=0-0"},
                        timeout=timeout,
                    )
                async with response_context as response:
                    content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                    if response.status < 400 and content_type and "/" in content_type:
                        return content_type
            except Exception as exc:
                log.debug("MAX media %s content type probe failed for %s: %s", method, url, exc)
        return None

    async def _update_chat_from_dispatch(self, payload: dict) -> None:
        chat_meta = payload.get("chat")
        if not isinstance(chat_meta, dict):
            log.debug(
                "MAX dispatch has no chat metadata chat_id=%s payload_keys=%s",
                payload.get("chatId"),
                sorted(payload.keys()),
            )
            return
        before_chat_id = chat_meta.get("id") or chat_meta.get("chatId")
        if before_chat_id is None:
            log.debug(
                "MAX dispatch chat metadata has no id payload_chat_id=%s chat_keys=%s",
                payload.get("chatId"),
                sorted(chat_meta.keys()),
            )
            return
        chat_id = str(before_chat_id)
        previous = self._snapshot_cache.chat_by_id(chat_id)
        previous_member_ids = {member.user_id for member in previous.members} if previous is not None else set()
        chat = self._snapshot_cache.register_snapshot_chat(chat_meta)
        if chat is None:
            return
        current_member_ids = {member.user_id for member in chat.members}
        removed_member_ids = sorted(previous_member_ids - current_member_ids)
        added_member_ids = sorted(current_member_ids - previous_member_ids)
        if removed_member_ids or added_member_ids:
            log.debug(
                "Updated MAX chat metadata from dispatch chat_id=%s members=%d added=%s removed=%s",
                chat.chat_id,
                len(chat.members),
                added_member_ids,
                removed_member_ids,
            )
        if previous is not None and previous == self._snapshot_cache.chat_by_id(chat_id):
            return
        if self._chat_handler is not None:
            await self._chat_handler(chat)

    def _queue_unknown_chat_message(self, chat_id: str, payload: dict) -> None:
        queue = self._pending_unknown_chat_payloads.setdefault(chat_id, [])
        queue.append(payload)
        task = self._unknown_chat_refresh_tasks.get(chat_id)
        if task is None or task.done():
            # MAX can deliver a message before the chat metadata arrives in the startup
            # snapshot. Hold payloads briefly and refresh metadata once per chat id.
            self._unknown_chat_refresh_tasks[chat_id] = asyncio.create_task(
                self._refresh_unknown_chat_and_deliver(chat_id)
            )

    async def _refresh_unknown_chat(self, chat_id: str) -> None:
        async with self._chat_refresh_lock:
            if self._snapshot_cache.has_chat(chat_id):
                return
            chats_count = max(self.initial_chats_count, len(self._snapshot_cache.chat_titles) + 20)
            log.debug("Refreshing MAX chat snapshot for unknown chat_id=%s", chat_id)
            try:
                response = await self._send_and_wait(
                    self.OP_AUTH_SNAPSHOT,
                    {
                        "chatsCount": chats_count,
                        "interactive": False,
                        "token": self.token,
                    },
                )
            except Exception:
                log.exception("Failed to refresh MAX chat snapshot for chat_id=%s", chat_id)
                return

            payload = response.get("payload") or {}
            if response.get("cmd") != 1 or payload.get("error"):
                detail = payload.get("error") or payload.get("localizedMessage") or "request rejected"
                log.warning(
                    "MAX chat snapshot refresh rejected for chat_id=%s: %s",
                    chat_id,
                    detail,
                )
                return
            await self._synchronize_snapshot_chats(payload)

    async def _refresh_unknown_chat_and_deliver(self, chat_id: str) -> None:
        try:
            await self._refresh_unknown_chat(chat_id)
            if self._snapshot_cache.has_chat(chat_id):
                await self._flush_pending_unknown_chat_payloads(chat_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Failed to process deferred MAX chat refresh for chat_id=%s", chat_id)
        finally:
            self._unknown_chat_refresh_tasks.pop(chat_id, None)

    async def _synchronize_snapshot_chats(self, payload: dict) -> None:
        try:
            chats = await self._update_snapshot_cache(payload)
            await self._dispatch_snapshot_contacts(chats)
        finally:
            self._contacts_ready.set()

    async def _update_snapshot_cache(self, payload: dict) -> list[MaxChat]:
        self._snapshot_cache.update_contact_names(payload)
        self._snapshot_cache.replace_address_book(payload)
        missing_ids = self._snapshot_cache.missing_dialog_contact_ids(payload)
        if missing_ids:
            # Dialog titles depend on contact names. If the snapshot references dialog
            # participants that are absent from contacts, fetch them before registering chats.
            try:
                response = await self._send_and_wait(
                    self.OP_CONTACTS_GET,
                    {"contactIds": [int(value) if value.isdigit() else value for value in missing_ids]},
                )
                self._snapshot_cache.update_contact_names(response.get("payload") or {})
            except Exception:
                log.exception("Failed to load MAX contact names for chat snapshot")
        chats = payload.get("chats") or []
        if not isinstance(chats, list):
            return []
        registered: list[MaxChat] = []
        for item in chats:
            if not isinstance(item, dict):
                continue
            chat = self._snapshot_cache.register_snapshot_chat(item)
            if chat is not None:
                registered.append(chat)
        return registered

    async def _dispatch_snapshot_contacts(self, chats: list[MaxChat]) -> None:
        if self._chat_handler is None:
            return
        synchronized = 0
        synchronized_chat_ids: set[str] = set()
        for contact in self._snapshot_cache.address_book.values():
            try:
                await self._chat_handler(
                    MaxChat(
                        chat_id=contact.chat_id,
                        title=contact.title,
                        raw=contact.raw,
                        avatar=contact.avatar,
                        force_roster_sync=True,
                    )
                )
                synchronized_chat_ids.add(contact.chat_id)
                synchronized += 1
            except Exception as exc:
                log.warning(
                    "Failed to synchronize MAX address book contact %s: %s",
                    contact.chat_id,
                    exc,
                )
        for chat in chats:
            if chat.is_group or chat.chat_id in synchronized_chat_ids:
                continue
            try:
                await self._chat_handler(
                    MaxChat(
                        chat_id=chat.chat_id,
                        title=chat.title,
                        raw=chat.raw,
                        avatar=chat.avatar,
                        force_roster_sync=True,
                    )
                )
                synchronized += 1
            except Exception as exc:
                log.warning(
                    "Failed to synchronize MAX direct snapshot chat %s: %s",
                    chat.chat_id,
                    exc,
                )
        if synchronized:
            log.info("Synchronized %s MAX contacts/direct chats from snapshot", synchronized)

    async def _flush_pending_unknown_chat_payloads(self, chat_id: str) -> None:
        pending = self._pending_unknown_chat_payloads.pop(chat_id, [])
        for payload in pending:
            await self._deliver_dispatch_payload(payload)

    async def _heartbeat(self) -> None:
        while self.ws is not None and not self.ws.closed:
            await asyncio.sleep(30)
            await self._send_json(self.OP_HEARTBEAT_PING, {"interactive": False})

    async def _send_and_wait(self, opcode: int, payload: dict, timeout: float = 20) -> dict:
        loop = asyncio.get_running_loop()
        future: asyncio.Future[dict] = loop.create_future()
        async with self._send_lock:
            if self.ws is None or self.ws.closed:
                raise RuntimeError("MAX personal WebSocket is not connected")
            seq = self._seq
            self._seq += 1
            self._pending[seq] = future
            await self.ws.send_json(
                {
                    "ver": 11,
                    "cmd": 0,
                    "seq": seq,
                    "opcode": opcode,
                    "payload": payload,
                }
            )
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        finally:
            self._pending.pop(seq, None)

    async def _wait_until_ready(self, timeout: float = 20) -> None:
        await asyncio.wait_for(self._ready.wait(), timeout=timeout)
        if self.ws is None or self.ws.closed:
            raise RuntimeError("MAX personal WebSocket is not connected")

    async def _send_json(self, opcode: int, payload: dict) -> int:
        if self.ws is None or self.ws.closed:
            raise RuntimeError("MAX personal WebSocket is not connected")
        async with self._send_lock:
            seq = self._seq
            self._seq += 1
            await self.ws.send_json(
                {
                    "ver": 11,
                    "cmd": 0,
                    "seq": seq,
                    "opcode": opcode,
                    "payload": payload,
                }
            )
            return seq

    @staticmethod
    def _extract_profile_id(payload: dict) -> Optional[str]:
        profile = payload.get("profile") or {}
        profile_id = profile.get("id")
        if profile_id is not None:
            return str(profile_id)
        contact = profile.get("contact") or {}
        contact_id = contact.get("id")
        return str(contact_id) if contact_id is not None else None

    @staticmethod
    def _extract_reply_to_message_id(message: dict) -> Optional[str]:
        link = message.get("link") or {}
        if not isinstance(link, dict):
            return None
        if str(link.get("type") or "").upper() != "REPLY":
            return None
        message_id = link.get("messageId")
        if message_id is not None:
            return str(message_id)
        linked_message = link.get("message") or {}
        if not isinstance(linked_message, dict):
            return None
        linked_message_id = linked_message.get("id")
        return str(linked_message_id) if linked_message_id is not None else None
