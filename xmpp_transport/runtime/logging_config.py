"""Private, backend-specific diagnostic logging."""

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path


_DIAGNOSTIC_LOGGERS = frozenset({
    "xmpp_transport.runtime.logging_config",
    "xmpp_transport.application.authentication",
    "xmpp_transport.adapters.events.in_memory",
    "xmpp_transport.adapters.backends.max.auth",
    "xmpp_transport.adapters.backends.max.plugin",
    "xmpp_transport.adapters.xmpp.auth_commands",
    "xmpp_transport.adapters.xmpp.gateway",
})


class _DiagnosticFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        # Other adapters can log message bodies or private media URLs at DEBUG.
        return record.name in _DIAGNOSTIC_LOGGERS


class _PrivateRotatingFileHandler(RotatingFileHandler):
    def _open(self):  # type: ignore[no-untyped-def]
        descriptor = os.open(self.baseFilename, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.fchmod(descriptor, 0o600)
        return os.fdopen(descriptor, self.mode, encoding=self.encoding)


def configure_backend_logging(backend_name: str, configured_path: str = "") -> Path:
    path = Path(configured_path or f"logs/xabber_transport_{backend_name}.log").expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handler = _PrivateRotatingFileHandler(
        str(path), maxBytes=10 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    handler.addFilter(_DiagnosticFilter())
    logger = logging.getLogger("xmpp_transport")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    for existing in tuple(logger.handlers):
        logger.removeHandler(existing)
        existing.close()
    logger.addHandler(handler)
    logger.info("Transport logging started backend_id=%s", backend_name)
    return path
