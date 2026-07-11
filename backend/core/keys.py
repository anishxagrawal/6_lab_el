from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# backend/.keys/ -- gitignored (see .gitignore), created on first run.
# This key signs scan reports for integrity verification. It is NOT used
# for anything user-data related (that's core/crypto.py's Fernet cipher +
# HMAC pepper) -- it exists purely so a /scan report can be proven
# untampered-with after the fact.
KEY_DIR = Path(__file__).resolve().parent.parent / ".keys"
PRIVATE_KEY_PATH = KEY_DIR / "report_signing_key.pem"


def load_or_create_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Loads DarkShield's own report-signing RSA keypair from backend/.keys/,
    generating one on first run and reusing it on every subsequent run.

    This is a 2048-bit RSA key used only to sign/verify scan report
    payloads (see security/report_signing.py) -- it is not involved in
    encrypting snippets or hashing secrets.
    """
    KEY_DIR.mkdir(exist_ok=True)

    if PRIVATE_KEY_PATH.exists():
        private_key = serialization.load_pem_private_key(
            PRIVATE_KEY_PATH.read_bytes(),
            password=None,
        )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise RuntimeError(
                f"{PRIVATE_KEY_PATH} does not contain an RSA private key"
            )
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        PRIVATE_KEY_PATH.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        # Private key material - not group/world readable.
        try:
            PRIVATE_KEY_PATH.chmod(0o600)
        except OSError:
            # Best-effort on platforms/filesystems that don't support chmod
            # (e.g. some CI/container setups) - not fatal.
            pass

    return private_key, private_key.public_key()