"""INI configuration parsing without importing concrete adapters."""

import os
from configparser import ConfigParser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional, Sequence


@dataclass(frozen=True)
class BackendConfig:
    name: str
    component_jid: str
    options: Mapping[str, str]
    component_password: Optional[str] = field(default=None, repr=False)


@dataclass(frozen=True)
class DatabaseConfig:
    dsn: str = field(repr=False)
    min_pool_size: int = 1
    max_pool_size: int = 10
    command_timeout: float = 30.0
    dsn_env: Optional[str] = None
    schema: str = "public"

    def __post_init__(self) -> None:
        if not self.dsn.strip() and not (self.dsn_env and self.dsn_env.strip()):
            raise ValueError("database dsn or dsn_env must be configured")
        if self.dsn.strip() and self.dsn_env:
            raise ValueError("database dsn and dsn_env are mutually exclusive")
        if not self.schema or not self.schema.replace("_", "a").isalnum():
            raise ValueError("database schema must be an SQL identifier")
        if self.min_pool_size < 1:
            raise ValueError("database min_pool_size must be positive")
        if self.max_pool_size < self.min_pool_size:
            raise ValueError("database max_pool_size must be at least min_pool_size")
        if self.command_timeout <= 0:
            raise ValueError("database command_timeout must be positive")

    def resolve(self, environment: Mapping[str, str]) -> "DatabaseConfig":
        if self.dsn:
            return self
        assert self.dsn_env is not None
        value = environment.get(self.dsn_env)
        if value is None or not value.strip():
            raise ValueError(
                "database DSN environment variable is not set: {}".format(self.dsn_env)
            )
        return DatabaseConfig(
            dsn=value,
            schema=self.schema,
            min_pool_size=self.min_pool_size,
            max_pool_size=self.max_pool_size,
            command_timeout=self.command_timeout,
        )


@dataclass(frozen=True)
class HttpConfig:
    host: str = "127.0.0.1"
    port: int = 8080

    def __post_init__(self) -> None:
        if not self.host.strip():
            raise ValueError("HTTP host must not be empty")
        if not 1 <= self.port <= 65535:
            raise ValueError("HTTP port must be between 1 and 65535")


@dataclass(frozen=True)
class RuntimeConfig:
    backends: Sequence[BackendConfig]
    database: Optional[DatabaseConfig] = None
    http: HttpConfig = HttpConfig()
    credential_key_env: str = "XABBER_TRANSPORT_CREDENTIAL_KEY"
    environment_file: Optional[Path] = None
    credential_key_value: Optional[str] = field(default=None, repr=False)
    iq_auth_secret: str = field(default="", repr=False)

    def credential_key(self, environment: Optional[Mapping[str, str]] = None) -> bytes:
        source = os.environ if environment is None else environment
        value = self.credential_key_value or source.get(self.credential_key_env)
        if value is None or not value.strip():
            raise ValueError(
                "credential encryption key environment variable is not set: {}".format(
                    self.credential_key_env
                )
            )
        try:
            return value.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("credential encryption key must be URL-safe base64") from None

    def resolved_environment(
        self, environment: Optional[Mapping[str, str]] = None
    ) -> Mapping[str, str]:
        result = {}
        if self.environment_file is not None:
            result.update(_read_dotenv(self.environment_file))
        result.update(os.environ if environment is None else environment)
        return result


def load_config(path: Path) -> RuntimeConfig:
    parser = ConfigParser()
    if not parser.read(str(path)):
        raise ValueError("configuration file not found: {}".format(path))

    backends = []
    for section in parser.sections():
        if not section.startswith("backend:"):
            continue
        name = section.partition(":")[2].strip()
        domain = _required(parser.get(section, "component_jid", fallback=None), section)
        options = dict(parser.items(section))
        options.pop("component_jid", None)
        component_password = options.pop("component_password", None)
        backends.append(
            BackendConfig(
                name=name,
                component_jid=domain,
                options=options,
                component_password=component_password,
            )
        )

    if not backends:
        raise ValueError("configuration must contain at least one [backend:<name>] section")
    database = _database_config(parser)
    key_environment = parser.get(
        "security",
        "credential_key_env",
        fallback="XABBER_TRANSPORT_CREDENTIAL_KEY",
    ).strip()
    if not key_environment:
        raise ValueError("security.credential_key_env must not be empty")
    key_value = parser.get("security", "credential_key", fallback="").strip() or None
    return RuntimeConfig(
        backends=tuple(backends),
        database=database,
        http=HttpConfig(
            host=parser.get("http", "host", fallback="127.0.0.1"),
            port=parser.getint("http", "port", fallback=8080),
        ),
        credential_key_env=key_environment,
        environment_file=_environment_file(parser, path),
        credential_key_value=key_value,
        iq_auth_secret=parser.get(
            "security", "iq_auth_secret", fallback=""
        ).strip(),
    )


def _required(value: Optional[str], section: str) -> str:
    if value is None or not value.strip():
        raise ValueError("{} must define component_jid".format(section))
    return value.strip()


def _database_config(parser: ConfigParser) -> Optional[DatabaseConfig]:
    if not parser.has_section("database"):
        return None
    dsn = parser.get("database", "dsn", fallback="").strip()
    dsn_env = parser.get("database", "dsn_env", fallback=None)
    return DatabaseConfig(
        dsn=dsn,
        dsn_env=dsn_env.strip() if dsn_env else None,
        schema=parser.get("database", "schema", fallback="public").strip(),
        min_pool_size=parser.getint("database", "min_pool_size", fallback=1),
        max_pool_size=parser.getint("database", "max_pool_size", fallback=10),
        command_timeout=parser.getfloat("database", "command_timeout", fallback=30.0),
    )


def _environment_file(parser: ConfigParser, config_path: Path) -> Optional[Path]:
    value = parser.get("environment", "file", fallback="").strip()
    if not value:
        return None
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = config_path.parent / path
    return path.resolve()


def _read_dotenv(path: Path) -> Mapping[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError("environment file cannot be read: {}".format(path)) from exc
    values = {}
    for number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or not key.replace("_", "a").isalnum() or key[0].isdigit():
            raise ValueError("invalid environment assignment at {}:{}".format(path, number))
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        values[key] = value
    return values
