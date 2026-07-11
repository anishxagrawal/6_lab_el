"""
Tests for core/crypto.py — HMAC-based secret hashing and Fernet-based
snippet encryption/decryption.
"""

from core.crypto import build_cipher, hash_secret, hmac_sha256_hex


class TestSnippetCipher:
    def test_encrypt_decrypt_roundtrip(self, fernet_key):
        cipher = build_cipher(fernet_key)
        original = "AWS_SECRET_ACCESS_KEY = 'super-fake-example-value'"

        encrypted = cipher.encrypt(original)
        decrypted = cipher.decrypt(encrypted)

        assert decrypted == original

    def test_encrypted_value_differs_from_plaintext(self, fernet_key):
        cipher = build_cipher(fernet_key)
        original = "password = 'hunter2'"

        encrypted = cipher.encrypt(original)

        assert encrypted != original
        assert isinstance(encrypted, str)

    def test_encrypt_empty_string_returns_empty(self, fernet_key):
        cipher = build_cipher(fernet_key)

        assert cipher.encrypt("") == ""

    def test_decrypt_empty_string_returns_empty(self, fernet_key):
        cipher = build_cipher(fernet_key)

        assert cipher.decrypt("") == ""

    def test_different_keys_cannot_decrypt_each_others_ciphertext(self, fernet_key):
        cipher_a = build_cipher(fernet_key)

        other_key = fernet_key
        while other_key == fernet_key:
            from cryptography.fernet import Fernet
            other_key = Fernet.generate_key().decode()
        cipher_b = build_cipher(other_key)

        encrypted = cipher_a.encrypt("top secret snippet")

        try:
            cipher_b.decrypt(encrypted)
            assert False, "decrypting with the wrong key should raise"
        except Exception:
            pass


class TestHashSecret:
    def test_hash_secret_is_stable(self, hmac_pepper):
        secret_value = "AKIAABCDEFGHIJKLMNOP"

        first_hash = hash_secret(secret_value, hmac_pepper)
        second_hash = hash_secret(secret_value, hmac_pepper)

        assert first_hash == second_hash

    def test_hash_secret_differs_with_different_pepper(self):
        secret_value = "AKIAABCDEFGHIJKLMNOP"

        hash_with_pepper_a = hash_secret(secret_value, "pepper-a")
        hash_with_pepper_b = hash_secret(secret_value, "pepper-b")

        assert hash_with_pepper_a != hash_with_pepper_b

    def test_hash_secret_strips_whitespace(self, hmac_pepper):
        assert hash_secret("  my-secret  ", hmac_pepper) == hash_secret("my-secret", hmac_pepper)

    def test_hash_secret_returns_hex_sha256_length(self, hmac_pepper):
        result = hash_secret("some-secret-value", hmac_pepper)

        # SHA-256 hex digest is always 64 characters
        assert len(result) == 64
        assert all(ch in "0123456789abcdef" for ch in result)


class TestHmacSha256Hex:
    def test_hmac_is_deterministic(self):
        assert hmac_sha256_hex("key", "value") == hmac_sha256_hex("key", "value")

    def test_hmac_changes_with_different_value(self):
        assert hmac_sha256_hex("key", "value-1") != hmac_sha256_hex("key", "value-2")