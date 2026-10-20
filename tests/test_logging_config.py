import logging
import os
import tempfile
import unittest
from pathlib import Path

from xmpp_transport.runtime.logging_config import configure_backend_logging


class BackendLoggingTests(unittest.TestCase):
    def test_debug_log_is_private_and_backend_specific(self) -> None:
        logger = logging.getLogger("xmpp_transport")
        previous_handlers = list(logger.handlers)
        previous_level = logger.level
        previous_propagate = logger.propagate
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "logs" / "max.log"
                configure_backend_logging("max", str(path))
                logging.getLogger("xmpp_transport.application.authentication").debug(
                    "password flow stage=%s", "submitted"
                )
                logging.getLogger("xmpp_transport.adapters.backends.max.client").debug(
                    "private message body should be filtered"
                )
                logging.getLogger("xmpp_transport.adapters.events.in_memory").error(
                    "Backend event dispatch failed event_type=contact.changed exception_type=IqError"
                )
                logger.handlers[0].flush()
                self.assertEqual(0o600, os.stat(path).st_mode & 0o777)
                self.assertIn("password flow stage=submitted", path.read_text())
                self.assertIn("event_type=contact.changed exception_type=IqError", path.read_text())
                self.assertNotIn("private message body", path.read_text())
        finally:
            for handler in list(logger.handlers):
                logger.removeHandler(handler)
                handler.close()
            for handler in previous_handlers:
                logger.addHandler(handler)
            logger.setLevel(previous_level)
            logger.propagate = previous_propagate
