"""Create a complete two-backend INI configuration with fresh secrets."""

import argparse
import os
import secrets
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Callable, Optional

from cryptography.fernet import Fernet


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="xabber-transport-create-config")
    parser.add_argument("--output", type=Path, default=Path("transports.ini"))
    parser.add_argument("--server-domain", default="example.com")
    parser.add_argument("--server-ip", default="127.0.0.1")
    parser.add_argument("--database-dsn", default=(
        "postgresql://transport_user:transport_password@127.0.0.1:5432/"
        "xmpp_transport"
    ))
    parser.add_argument("--telegram-api-id", type=int)
    parser.add_argument("--telegram-api-hash", default="")
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace the output file if it already exists",
    )
    return parser.parse_args(argv)


def build_config(
    args: argparse.Namespace,
    secret_factory: Callable[[int], str] = secrets.token_urlsafe,
    credential_key: Optional[str] = None,
) -> str:
    if args.telegram_api_id is not None and args.telegram_api_id <= 0:
        raise ValueError("telegram-api-id must be positive")
    values = {
        "server_domain": _ini_value(args.server_domain, "server-domain"),
        "server_ip": _ini_value(args.server_ip, "server-ip"),
        "database_dsn": _ini_value(args.database_dsn, "database-dsn"),
        "telegram_api_hash": _optional_ini_value(
            args.telegram_api_hash, "telegram-api-hash"
        ),
        "max_component_password": secret_factory(48),
        "telegram_component_password": secret_factory(48),
        "media_url_secret": secret_factory(48),
        "iq_auth_secret": secret_factory(48),
        "credential_key": credential_key or Fernet.generate_key().decode("ascii"),
        "telegram_api_id": (
            str(args.telegram_api_id) if args.telegram_api_id is not None else ""
        ),
    }
    return """[backend:max]
component_jid = max.{server_domain}
server_ip = {server_ip}
server_port = 5237
component_connect_timeout = 20
component_password = {max_component_password}
control_localpart = bot
server_domain = {server_domain}
http_host = 127.0.0.1
http_port = 8089
qr_storage_dir = data/login_qr/max
qr_base_url = http://127.0.0.1:8089
qr_max_age_seconds = 3600
qr_cleanup_interval_seconds = 3600
contacts_page_size = 20
roster_group = MAX
test_self_messages = false

[backend:telegram]
component_jid = telegram.{server_domain}
server_ip = {server_ip}
server_port = 5238
component_connect_timeout = 20
component_password = {telegram_component_password}
control_localpart = bot
server_domain = {server_domain}
http_host = 127.0.0.1
http_port = 8088
qr_storage_dir = data/login_qr/telegram
qr_base_url = http://127.0.0.1:8088
qr_max_age_seconds = 3600
qr_cleanup_interval_seconds = 3600
api_id = {telegram_api_id}
api_hash = {telegram_api_hash}
media_url_secret = {media_url_secret}
media_stream_request_size = 524288
media_base_url = http://127.0.0.1:8088
avatar_base_url = http://127.0.0.1:8088
avatar_storage_dir = data/avatars/telegram
avatar_max_bytes = 524288
avatar_unreferenced_ttl_days = 7
avatar_cleanup_interval_seconds = 86400
contacts_page_size = 20
roster_group = Telegram
test_self_messages = false

[database]
dsn = {database_dsn}
schema = public
min_pool_size = 1
max_pool_size = 5
command_timeout = 30

[security]
credential_key = {credential_key}
iq_auth_secret = {iq_auth_secret}
""".format(**values)


def create_config(args: argparse.Namespace) -> Path:
    output = args.output.expanduser().resolve()
    if output.exists() and not args.force:
        raise FileExistsError(
            f"configuration already exists: {output} (use --force to replace it)"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_TRUNC if args.force else os.O_EXCL
    descriptor = os.open(str(output), flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(build_config(args))
    os.chmod(str(output), 0o600)
    return output


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    try:
        output = create_config(args)
    except (FileExistsError, OSError, ValueError) as exc:
        print(f"configuration creation failed: {exc}", file=sys.stderr)
        return 2
    print(f"configuration created: {output}")
    return 0


def _ini_value(value: str, option: str) -> str:
    normalized = value.strip()
    if not normalized or "\n" in normalized or "\r" in normalized:
        raise ValueError(f"{option} must be a non-empty single-line value")
    return normalized


def _optional_ini_value(value: str, option: str) -> str:
    normalized = value.strip()
    if "\n" in normalized or "\r" in normalized:
        raise ValueError(f"{option} must be a single-line value")
    return normalized


if __name__ == "__main__":
    raise SystemExit(main())
