import os
import tempfile
import unittest
from pathlib import Path

from xmpp_transport.runtime.config import load_config
from xmpp_transport.runtime.create_config import build_config, create_config, parse_args


class CreateConfigTests(unittest.TestCase):
    def test_generates_only_selected_backend_with_shared_settings(self) -> None:
        for backend, secret_count in (("max", 1), ("telegram", 2)):
            with self.subTest(backend=backend), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "transport.ini"
                args = parse_args(("--backend", backend, "--output", str(path)))
                calls = []

                def secret_factory(size):  # type: ignore[no-untyped-def]
                    calls.append(size)
                    return "generated-secret"

                path.write_text(build_config(args, secret_factory), encoding="utf-8")
                config = load_config(path)
                self.assertEqual([backend], [item.name for item in config.backends])
                self.assertIsNotNone(config.database)
                self.assertNotIn("iq_auth_secret", path.read_text(encoding="utf-8"))
                self.assertEqual(secret_count, len(calls))
                self.assertEqual(
                    backend == "telegram", "api_id" in config.backends[0].options
                )

    def test_invalid_config_does_not_truncate_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "transport.ini"
            path.write_text("existing settings", encoding="utf-8")
            args = parse_args((
                "--backend", "telegram", "--telegram-api-id", "-1",
                "--output", str(path), "--force",
            ))
            with self.assertRaises(ValueError):
                create_config(args)
            self.assertEqual("existing settings", path.read_text(encoding="utf-8"))

    def _args(self, output: Path):  # type: ignore[no-untyped-def]
        return parse_args(
            (
                "--output",
                str(output),
                "--telegram-api-id",
                "123456",
                "--telegram-api-hash",
                "telegram-api-hash",
            )
        )

    def test_builds_complete_max_and_telegram_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "transports.ini"
            args = self._args(path)
            sequence = iter(("max-secret", "telegram-secret", "media-secret"))
            content = build_config(
                args,
                secret_factory=lambda _size: next(sequence),
                credential_key="credential-key",
            )
            path.write_text(content, encoding="utf-8")
            config = load_config(path)

        backends = {backend.name: backend for backend in config.backends}
        self.assertEqual("5237", backends["max"].options["server_port"])
        self.assertEqual("8089", backends["max"].options["http_port"])
        self.assertEqual("data/login_qr/max", backends["max"].options["qr_storage_dir"])
        self.assertEqual(
            "http://127.0.0.1:8089", backends["max"].options["qr_base_url"]
        )
        self.assertEqual("5238", backends["telegram"].options["server_port"])
        self.assertEqual("8088", backends["telegram"].options["http_port"])
        self.assertEqual(
            "data/login_qr/telegram",
            backends["telegram"].options["qr_storage_dir"],
        )
        self.assertEqual("media-secret", backends["telegram"].options["media_url_secret"])
        self.assertNotIn("iq_auth_secret", content)

    def test_creates_private_file_and_refuses_implicit_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "transports.ini"
            args = self._args(path)

            self.assertEqual(path.resolve(), create_config(args))
            self.assertEqual(0o600, os.stat(path).st_mode & 0o777)
            with self.assertRaises(FileExistsError):
                create_config(args)

    def test_leaves_optional_telegram_api_fields_empty(self) -> None:
        args = parse_args(())

        content = build_config(
            args,
            secret_factory=lambda _size: "generated-secret-at-least-32-bytes",
            credential_key="credential-key",
        )

        self.assertIn("api_id = \n", content)
        self.assertIn("api_hash = \n", content)


if __name__ == "__main__":
    unittest.main()
