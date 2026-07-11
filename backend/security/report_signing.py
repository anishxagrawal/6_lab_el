from __future__ import annotations

import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def canonical_report_bytes(report: dict[str, Any]) -> bytes:
    """
    Deterministic JSON encoding of a report payload so that sign() and
    verify() always agree byte-for-byte, regardless of dict key insertion
    order on either side (e.g. reconstructed from a DB row vs. built fresh
    in-process).
    """
    return json.dumps(report, sort_keys=True, separators=(",", ":")).encode()


def sign_report(report: dict[str, Any], private_key: rsa.RSAPrivateKey) -> str:
    """
    RSA-PSS/SHA-256 signs the canonical bytes of `report`. Returns the
    signature as a hex string (convenient for storing in a `text` DB
    column and for round-tripping through JSON request/response bodies).
    """
    payload = canonical_report_bytes(report)
    signature = private_key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature.hex()


def verify_report(
    report: dict[str, Any],
    signature_hex: str,
    public_key: rsa.RSAPublicKey,
) -> bool:
    """
    Returns True if `signature_hex` is a valid RSA-PSS/SHA-256 signature of
    `report` under `public_key`, False otherwise (including malformed hex,
    wrong key, or a report payload that was mutated after signing).
    """
    try:
        signature_bytes = bytes.fromhex(signature_hex)
    except (ValueError, TypeError):
        return False

    try:
        public_key.verify(
            signature_bytes,
            canonical_report_bytes(report),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def public_key_to_pem(public_key: rsa.RSAPublicKey) -> str:
    """PEM-encode a public key for the /reports/public-key endpoint."""
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_bytes.decode()