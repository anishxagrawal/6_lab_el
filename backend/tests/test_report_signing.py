"""
Tests for core/keys.py + security/report_signing.py — the RSA-PSS
digital-signature layer used to sign and independently verify scan reports.
"""

from __future__ import annotations

import copy

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from core.keys import load_or_create_keypair
from security.report_signing import (
    canonical_report_bytes,
    public_key_to_pem,
    sign_report,
    verify_report,
)


@pytest.fixture
def keypair(tmp_path, monkeypatch):
    """A fresh RSA keypair written to a throwaway .keys/ dir per test."""
    import core.keys as keys_module

    monkeypatch.setattr(keys_module, "KEY_DIR", tmp_path / ".keys")
    monkeypatch.setattr(
        keys_module, "PRIVATE_KEY_PATH", tmp_path / ".keys" / "report_signing_key.pem"
    )
    return load_or_create_keypair()


@pytest.fixture
def sample_report() -> dict:
    return {
        "repo_id": "11111111-1111-1111-1111-111111111111",
        "owner": "octocat",
        "name": "hello-world",
        "github_url": "https://github.com/octocat/hello-world",
        "total_findings": 7,
        "critical_findings": 2,
        "generated_at": "2026-07-11T00:00:00+00:00",
    }


class TestKeypairGeneration:
    def test_generates_rsa_2048_keypair(self, keypair):
        private_key, public_key = keypair
        assert isinstance(private_key, rsa.RSAPrivateKey)
        assert isinstance(public_key, rsa.RSAPublicKey)
        assert private_key.key_size == 2048

    def test_private_key_file_is_created_once_and_reused(self, tmp_path, monkeypatch):
        import core.keys as keys_module

        monkeypatch.setattr(keys_module, "KEY_DIR", tmp_path / ".keys")
        monkeypatch.setattr(
            keys_module,
            "PRIVATE_KEY_PATH",
            tmp_path / ".keys" / "report_signing_key.pem",
        )

        def to_pem(private_key):
            return private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

        private_key_1, public_key_1 = load_or_create_keypair()
        pem_1 = to_pem(private_key_1)

        # Second call must load the same key from disk, not regenerate.
        private_key_2, public_key_2 = load_or_create_keypair()
        pem_2 = to_pem(private_key_2)

        assert pem_1 == pem_2


class TestCanonicalReportBytes:
    def test_key_order_does_not_affect_canonical_bytes(self, sample_report):
        reordered = {k: sample_report[k] for k in reversed(list(sample_report))}
        assert canonical_report_bytes(sample_report) == canonical_report_bytes(reordered)

    def test_different_content_produces_different_bytes(self, sample_report):
        mutated = copy.deepcopy(sample_report)
        mutated["total_findings"] += 1
        assert canonical_report_bytes(sample_report) != canonical_report_bytes(mutated)


class TestSignAndVerify:
    def test_valid_signature_verifies(self, keypair, sample_report):
        private_key, public_key = keypair
        signature = sign_report(sample_report, private_key)

        assert verify_report(sample_report, signature, public_key) is True

    def test_tampered_report_fails_verification(self, keypair, sample_report):
        private_key, public_key = keypair
        signature = sign_report(sample_report, private_key)

        tampered = copy.deepcopy(sample_report)
        tampered["critical_findings"] = 999

        assert verify_report(tampered, signature, public_key) is False

    def test_single_character_change_fails_verification(self, keypair, sample_report):
        private_key, public_key = keypair
        signature = sign_report(sample_report, private_key)

        tampered = copy.deepcopy(sample_report)
        tampered["owner"] = tampered["owner"] + "x"

        assert verify_report(tampered, signature, public_key) is False

    def test_signature_from_wrong_key_fails_verification(self, sample_report, tmp_path, monkeypatch):
        import core.keys as keys_module

        monkeypatch.setattr(keys_module, "KEY_DIR", tmp_path / "keys_a")
        monkeypatch.setattr(
            keys_module, "PRIVATE_KEY_PATH", tmp_path / "keys_a" / "report_signing_key.pem"
        )
        private_key_a, _ = load_or_create_keypair()

        monkeypatch.setattr(keys_module, "KEY_DIR", tmp_path / "keys_b")
        monkeypatch.setattr(
            keys_module, "PRIVATE_KEY_PATH", tmp_path / "keys_b" / "report_signing_key.pem"
        )
        _, public_key_b = load_or_create_keypair()

        signature = sign_report(sample_report, private_key_a)

        assert verify_report(sample_report, signature, public_key_b) is False

    def test_malformed_signature_hex_returns_false_not_raise(self, keypair, sample_report):
        _, public_key = keypair

        assert verify_report(sample_report, "not-valid-hex!!", public_key) is False

    def test_empty_signature_returns_false(self, keypair, sample_report):
        _, public_key = keypair

        assert verify_report(sample_report, "", public_key) is False


class TestPublicKeyPem:
    def test_public_key_pem_has_expected_header(self, keypair):
        _, public_key = keypair
        pem = public_key_to_pem(public_key)

        assert pem.startswith("-----BEGIN PUBLIC KEY-----")
        assert pem.strip().endswith("-----END PUBLIC KEY-----")