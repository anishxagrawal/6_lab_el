import base64
import hashlib
import hmac

from cryptography.fernet import Fernet


def hmac_sha256_hex(secret: str, value: str) -> str:
    return hmac.new(
        secret.encode(),
        value.encode(),
        hashlib.sha256,
    ).hexdigest()


def hash_secret(
    secret: str,
    pepper: str,
) -> str:
    """
    Stable secret fingerprint.
    """

    normalized = secret.strip()

    return hmac_sha256_hex(
        pepper,
        normalized,
    )


class SnippetCipher:
    """
    Handles encryption/decryption
    of code snippets stored in DB.
    """

    def __init__(
        self,
        encryption_key: str,
    ):

        self._fernet = Fernet(
            encryption_key.encode()
        )

    def encrypt(
        self,
        value: str,
    ) -> str:

        if not value:
            return ""

        encrypted = (
            self._fernet.encrypt(
                value.encode()
            )
        )

        return (
            base64.b64encode(
                encrypted
            )
            .decode()
        )

    def decrypt(
        self,
        value: str,
    ) -> str:

        if not value:
            return ""

        encrypted = (
            base64.b64decode(
                value.encode()
            )
        )

        return (
            self._fernet.decrypt(
                encrypted
            )
            .decode()
        )


def build_cipher(
    encryption_key: str,
) -> SnippetCipher:

    return SnippetCipher(
        encryption_key
    )