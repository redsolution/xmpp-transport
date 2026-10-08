"""Persistent SVG login QR images served by the runtime HTTP listener."""

import asyncio
import io
import logging
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import qrcode
import qrcode.image.svg


log = logging.getLogger(__name__)


@dataclass(frozen=True)
class StoredQrImage:
    url: str
    name: str
    mime_type: str
    size: int


class QrCodeStore:
    """Create public SVG QR files and remove expired files owned by one backend."""

    MIME_TYPE = "image/svg+xml"

    def __init__(
        self,
        storage_dir: str,
        base_url: str,
        backend_name: str,
        max_age_seconds: int = 3600,
        cleanup_interval_seconds: int = 3600,
    ) -> None:
        if not backend_name or any(
            not (character.isalnum() or character in ("-", "_"))
            for character in backend_name
        ):
            raise ValueError("backend name is not safe for login QR filenames")
        self.storage_dir = Path(storage_dir)
        self._url_prefix = "{}/qr".format(base_url.rstrip("/"))
        self._filename_prefix = "{}-login-qr-".format(backend_name)
        self._max_age_seconds = max_age_seconds
        self._cleanup_interval_seconds = cleanup_interval_seconds
        self._stop = asyncio.Event()
        self._task: Optional[asyncio.Task[None]] = None

    def create(self, value: str) -> StoredQrImage:
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        content = self._svg_content(value)
        for _attempt in range(10):
            name = "{}{}.svg".format(self._filename_prefix, secrets.token_urlsafe(24))
            path = self.storage_dir / name
            try:
                with path.open("xb") as stream:
                    stream.write(content)
                break
            except FileExistsError:
                continue
        else:
            raise RuntimeError("could not allocate unique login QR filename")
        return StoredQrImage(
            url="{}/{}".format(self._url_prefix, name),
            name=name,
            mime_type=self.MIME_TYPE,
            size=len(content),
        )

    async def start(self) -> None:
        if self._task is not None:
            return
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._task = asyncio.create_task(self._cleanup_loop(), name="login-qr-cleanup")

    async def close(self) -> None:
        task = self._task
        self._task = None
        self._stop.set()
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    def cleanup(self, now: Optional[float] = None) -> int:
        cutoff = (time.time() if now is None else now) - self._max_age_seconds
        removed = 0
        pattern = "{}*.svg".format(self._filename_prefix)
        for path in self.storage_dir.glob(pattern):
            try:
                if path.stat().st_mtime > cutoff:
                    continue
                path.unlink()
                removed += 1
            except FileNotFoundError:
                continue
        return removed

    async def _cleanup_loop(self) -> None:
        while not self._stop.is_set():
            try:
                removed = self.cleanup()
                if removed:
                    log.info("Removed %s expired login QR file(s)", removed)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Login QR cleanup failed")
            try:
                await asyncio.wait_for(
                    self._stop.wait(), timeout=max(self._cleanup_interval_seconds, 1)
                )
            except asyncio.TimeoutError:
                continue

    @staticmethod
    def _svg_content(value: str) -> bytes:
        image = qrcode.make(value, image_factory=qrcode.image.svg.SvgImage)
        stream = io.BytesIO()
        image.save(stream)
        return QrCodeStore._with_white_background(stream.getvalue())

    @staticmethod
    def _with_white_background(content: bytes) -> bytes:
        svg_start = content.find(b"<svg")
        if svg_start < 0:
            return content
        tag_end = content.find(b">", svg_start)
        if tag_end < 0:
            return content
        background = b'<rect width="100%" height="100%" fill="#fff"/>'
        insert_at = tag_end + 1
        return content[:insert_at] + background + content[insert_at:]
