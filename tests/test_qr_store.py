import asyncio
import os
import tempfile
import unittest
from pathlib import Path

from xmpp_transport.adapters.web.qr import QrCodeStore


class QrCodeStoreTests(unittest.TestCase):
    def test_stores_svg_and_returns_public_url(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = QrCodeStore(
                directory,
                "https://transport.example/",
                "max",
            )

            image = store.create("https://max.example/login")

            self.assertTrue(image.name.startswith("max-login-qr-"))
            self.assertTrue(image.name.endswith(".svg"))
            self.assertEqual("image/svg+xml", image.mime_type)
            self.assertEqual(
                "https://transport.example/qr/{}".format(image.name), image.url
            )
            content = (Path(directory) / image.name).read_bytes()
            self.assertTrue(content.startswith(b"<?xml"))
            self.assertIn(b"<svg", content)
            self.assertIn(
                b'<rect width="100%" height="100%" fill="#fff"/>', content
            )
            self.assertEqual(len(content), image.size)

    def test_cleanup_only_removes_expired_files_for_backend(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old_qr = root / "telegram-login-qr-old.svg"
            fresh_qr = root / "telegram-login-qr-fresh.svg"
            other_backend = root / "max-login-qr-old.svg"
            unrelated = root / "other.svg"
            for path in (old_qr, fresh_qr, other_backend, unrelated):
                path.write_text("<svg/>", encoding="utf-8")
            os.utime(str(old_qr), (1000, 1000))
            os.utime(str(fresh_qr), (2000, 2000))
            os.utime(str(other_backend), (1000, 1000))
            os.utime(str(unrelated), (1000, 1000))
            store = QrCodeStore(
                directory,
                "https://transport.example",
                "telegram",
                max_age_seconds=500,
            )

            removed = store.cleanup(now=2000)

            self.assertEqual(1, removed)
            self.assertFalse(old_qr.exists())
            self.assertTrue(fresh_qr.exists())
            self.assertTrue(other_backend.exists())
            self.assertTrue(unrelated.exists())


class QrCleanupLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_start_runs_cleanup_and_close_stops_task(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            old_qr = Path(directory) / "max-login-qr-old.svg"
            old_qr.write_text("<svg/>", encoding="utf-8")
            os.utime(str(old_qr), (1000, 1000))
            store = QrCodeStore(
                directory,
                "https://transport.example",
                "max",
                max_age_seconds=500,
            )

            await store.start()
            await asyncio.sleep(0)
            await store.close()

            self.assertFalse(old_qr.exists())


if __name__ == "__main__":
    unittest.main()
