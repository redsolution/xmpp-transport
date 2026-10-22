"""Authenticated encryption for provider credential payloads."""

import base64
import hashlib
import hmac

from cryptography.fernet import Fernet, InvalidToken

from xmpp_transport.domain.errors import TransportError
from xmpp_transport.domain.identifiers import BackendId


class CredentialDecryptionError(TransportError):
    """Stored credentials cannot be authenticated or decrypted."""


class FernetCredentialCipher:
    def __init__(self, key: bytes) -> None:
        try:
            self._fernet = Fernet(key)
            self._account_key_secret = base64.urlsafe_b64decode(key)
        except (TypeError, ValueError) as exc:
            raise ValueError("credential encryption key is invalid") from exc

    def encrypt(self, plaintext: bytes) -> bytes:
        if not plaintext:
            raise ValueError("credential payload must not be empty")
        return self._fernet.encrypt(plaintext)

    def decrypt(self, encrypted: bytes) -> bytes:
        if not encrypted:
            raise CredentialDecryptionError("stored credential payload is invalid")
        try:
            return self._fernet.decrypt(encrypted)
        except InvalidToken as exc:
            raise CredentialDecryptionError("stored credential payload is invalid") from exc

    def remote_account_key(self, backend_id: BackendId, account_id: str) -> bytes:
        value = b"xmpp-transport:remote-account:v1\0" + str(backend_id).encode("utf-8")
        value += b"\0" + account_id.encode("utf-8")
        return hmac.new(self._account_key_secret, value, hashlib.sha256).digest()
