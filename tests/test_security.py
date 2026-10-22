import unittest

from cryptography.fernet import Fernet

from xmpp_transport.adapters.security import CredentialDecryptionError, FernetCredentialCipher
from xmpp_transport.domain.identifiers import BackendId


class FernetCredentialCipherTests(unittest.TestCase):
    def test_remote_account_key_is_stable_and_scoped(self) -> None:
        key = Fernet.generate_key()
        first = FernetCredentialCipher(key)
        second = FernetCredentialCipher(key)

        digest = first.remote_account_key(BackendId("max"), "12345")

        self.assertEqual(digest, second.remote_account_key(BackendId("max"), "12345"))
        self.assertNotEqual(digest, first.remote_account_key(BackendId("max"), "54321"))
        self.assertNotEqual(digest, first.remote_account_key(BackendId("telegram"), "12345"))
        self.assertNotIn(b"12345", digest)

    def test_round_trip(self) -> None:
        cipher = FernetCredentialCipher(Fernet.generate_key())
        encrypted = cipher.encrypt(b"provider-session")
        self.assertNotIn(b"provider-session", encrypted)
        self.assertEqual(b"provider-session", cipher.decrypt(encrypted))

    def test_wrong_key_is_normalized_without_token_disclosure(self) -> None:
        encrypted = FernetCredentialCipher(Fernet.generate_key()).encrypt(b"private")
        cipher = FernetCredentialCipher(Fernet.generate_key())
        with self.assertRaises(CredentialDecryptionError) as context:
            cipher.decrypt(encrypted)
        self.assertNotIn(encrypted.decode("ascii"), str(context.exception))

    def test_invalid_key_is_normalized(self) -> None:
        with self.assertRaisesRegex(ValueError, "key is invalid"):
            FernetCredentialCipher(b"not-a-fernet-key")

    def test_empty_plaintext_is_rejected(self) -> None:
        cipher = FernetCredentialCipher(Fernet.generate_key())
        with self.assertRaises(ValueError):
            cipher.encrypt(b"")


if __name__ == "__main__":
    unittest.main()
