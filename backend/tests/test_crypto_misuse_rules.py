"""
Tests for the custom crypto-misuse Semgrep rule pack
(security/semgrep/rules/crypto_misuse.yml).

These tests invoke Semgrep directly against the rule file, rather than
going through the full scan pipeline, so they don't depend on network
access to the Semgrep registry (the default SEMGREP_CONFIG="auto" fetches
rules from semgrep.dev, which isn't available in sandboxed/CI runners).
The registry-based "auto" config is exercised separately by
test_semgrep_pipeline_uses_custom_rules below, which monkeypatches
SEMGREP_CONFIG to point at a local file instead.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from security.semgrep import runner as runner_module
from security.semgrep.constants import BASE_DIR
from security.semgrep.service import SemgrepService

RULES_PATH = BASE_DIR / "rules" / "crypto_misuse.yml"

SEMGREP_AVAILABLE = shutil.which("semgrep") is not None or shutil.which("pysemgrep") is not None

pytestmark = pytest.mark.skipif(
    not SEMGREP_AVAILABLE,
    reason="semgrep executable not found on PATH",
)


def _run_crypto_misuse_only(file_path: Path) -> dict:
    """
    Run only the crypto-misuse rule pack (no registry "auto" config)
    against a single file, and return the parsed Semgrep JSON.
    """

    command = [
        shutil.which("semgrep") or shutil.which("pysemgrep"),
        "scan",
        "--config",
        str(RULES_PATH),
        "--json",
        str(file_path),
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode in (0, 1), result.stderr

    return json.loads(result.stdout)


def _check_ids(semgrep_json: dict) -> list[str]:
    """
    Return normalized rule ids from a Semgrep JSON result set.

    For local (non-registry) configs, Semgrep prefixes check_id with a
    dotted namespace derived from the config file's directory path
    relative to cwd (e.g. "security.semgrep.rules.weak-hash-md5-sha1").
    Since our rule ids use hyphens (never dots), the real id is always
    the last dot-separated segment, so this strips the prefix rather
    than asserting against it.
    """

    return [r["check_id"].rsplit(".", 1)[-1] for r in semgrep_json.get("results", [])]


class TestRulePackIsValid:
    def test_rule_file_exists(self):
        assert RULES_PATH.exists()

    def test_semgrep_validate_reports_no_errors(self):
        command = [
            shutil.which("semgrep") or shutil.which("pysemgrep"),
            "--validate",
            "--config",
            str(RULES_PATH),
        ]

        result = subprocess.run(command, capture_output=True, text=True, timeout=60)

        assert "0 configuration error" in (result.stdout + result.stderr)


class TestPythonCryptoMisuseDetection:
    def test_detects_md5_and_sha1(self, tmp_path):
        sample = tmp_path / "bad.py"
        sample.write_text(
            "import hashlib\n"
            "hashlib.md5(b'x')\n"
            "hashlib.sha1(b'y')\n"
        )

        ids = _check_ids(_run_crypto_misuse_only(sample))

        assert ids.count("weak-hash-md5-sha1") == 2

    def test_detects_hardcoded_iv(self, tmp_path):
        sample = tmp_path / "bad.py"
        sample.write_text(
            "from Crypto.Cipher import AES\n"
            "cipher = AES.new(key, AES.MODE_CBC, b'0000000000000000')\n"
        )

        assert "hardcoded-iv" in _check_ids(_run_crypto_misuse_only(sample))

    def test_detects_ecb_mode(self, tmp_path):
        sample = tmp_path / "bad.py"
        sample.write_text(
            "from Crypto.Cipher import AES\n"
            "cipher = AES.new(key, AES.MODE_ECB)\n"
        )

        assert "insecure-cipher-mode-ecb" in _check_ids(_run_crypto_misuse_only(sample))

    def test_detects_weak_rsa_key_size(self, tmp_path):
        sample = tmp_path / "bad.py"
        sample.write_text(
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
        )

        assert "weak-rsa-key-size" in _check_ids(_run_crypto_misuse_only(sample))

    def test_allows_strong_rsa_key_size(self, tmp_path):
        sample = tmp_path / "good.py"
        sample.write_text(
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "rsa.generate_private_key(public_exponent=65537, key_size=4096)\n"
        )

        assert "weak-rsa-key-size" not in _check_ids(_run_crypto_misuse_only(sample))

    def test_detects_insecure_random_for_token(self, tmp_path):
        sample = tmp_path / "bad.py"
        sample.write_text(
            "import random\n"
            "def generate_session_token():\n"
            "    return random.choice('abcdef')\n"
        )

        assert "insecure-random-for-security" in _check_ids(_run_crypto_misuse_only(sample))

    def test_does_not_flag_random_in_unrelated_function(self, tmp_path):
        sample = tmp_path / "good.py"
        sample.write_text(
            "import random\n"
            "def shuffle_deck():\n"
            "    return random.choice(['a', 'b'])\n"
        )

        assert "insecure-random-for-security" not in _check_ids(_run_crypto_misuse_only(sample))

    def test_no_findings_on_secure_python_code(self, tmp_path):
        sample = tmp_path / "good.py"
        sample.write_text(
            "import bcrypt\n"
            "import secrets\n"
            "from Crypto.Cipher import AES\n"
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "\n"
            "def hash_password(password):\n"
            "    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n"
            "\n"
            "def encrypt(key, data):\n"
            "    iv = secrets.token_bytes(16)\n"
            "    cipher = AES.new(key, AES.MODE_GCM)\n"
            "    return cipher.encrypt(data)\n"
            "\n"
            "def make_key():\n"
            "    return rsa.generate_private_key(public_exponent=65537, key_size=4096)\n"
            "\n"
            "def token():\n"
            "    return secrets.token_hex(16)\n"
        )

        assert _check_ids(_run_crypto_misuse_only(sample)) == []


class TestJavaScriptCryptoMisuseDetection:
    def test_detects_md5(self, tmp_path):
        sample = tmp_path / "bad.js"
        sample.write_text("crypto.createHash('md5').update(x).digest('hex');\n")

        assert "weak-hash-md5-sha1-js" in _check_ids(_run_crypto_misuse_only(sample))

    def test_detects_ecb_mode(self, tmp_path):
        sample = tmp_path / "bad.js"
        sample.write_text("crypto.createCipheriv('aes-128-ecb', key, null);\n")

        assert "insecure-cipher-mode-ecb-js" in _check_ids(_run_crypto_misuse_only(sample))

    def test_detects_weak_rsa_key_size(self, tmp_path):
        sample = tmp_path / "bad.js"
        sample.write_text("crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });\n")

        assert "weak-rsa-key-size-js" in _check_ids(_run_crypto_misuse_only(sample))

    def test_allows_strong_rsa_key_size(self, tmp_path):
        sample = tmp_path / "good.js"
        sample.write_text("crypto.generateKeyPairSync('rsa', { modulusLength: 4096 });\n")

        assert "weak-rsa-key-size-js" not in _check_ids(_run_crypto_misuse_only(sample))

    def test_detects_math_random(self, tmp_path):
        sample = tmp_path / "bad.js"
        sample.write_text("const token = Math.random().toString(36);\n")

        assert "insecure-random-for-security-js" in _check_ids(_run_crypto_misuse_only(sample))

    def test_no_findings_on_secure_js_code(self, tmp_path):
        sample = tmp_path / "good.js"
        sample.write_text(
            "const crypto = require('crypto');\n"
            "crypto.createHash('sha256').update(x).digest('hex');\n"
            "crypto.createCipheriv('aes-256-gcm', key, iv);\n"
            "crypto.generateKeyPairSync('rsa', { modulusLength: 4096 });\n"
            "crypto.randomBytes(16).toString('hex');\n"
        )

        assert _check_ids(_run_crypto_misuse_only(sample)) == []


class TestOwaspMapping:
    def test_crypto_misuse_rule_ids_map_to_cryptographic_failures(self):
        from security.semgrep.mapper import map_to_owasp

        for rule_id in [
            "weak-hash-md5-sha1",
            "hardcoded-iv",
            "weak-rsa-key-size",
            "insecure-cipher-mode-ecb",
            "insecure-random-for-security",
            "weak-hash-md5-sha1-js",
            "insecure-cipher-mode-ecb-js",
            "weak-rsa-key-size-js",
        ]:
            assert map_to_owasp(rule_id) == "A02:2021"


class TestSemgrepPipelineIntegration:
    def test_semgrep_pipeline_uses_custom_rules(self, tmp_path, monkeypatch):
        """
        End-to-end check that SemgrepService.analyze_repository picks up
        crypto-misuse findings when run through the real pipeline (parser,
        OWASP mapper, statistics), not just the raw semgrep invocation.

        SEMGREP_CONFIG is monkeypatched to the local rule file (instead of
        "auto") purely to avoid a network call to the Semgrep registry in
        this test environment; CUSTOM_RULE_PATHS is cleared so the rule
        pack isn't scanned twice.
        """

        monkeypatch.setattr(runner_module, "SEMGREP_CONFIG", str(RULES_PATH))
        monkeypatch.setattr(runner_module, "CUSTOM_RULE_PATHS", [])

        target_dir = tmp_path / "repo"
        target_dir.mkdir()
        (target_dir / "app.py").write_text(
            "import hashlib\n"
            "hashlib.md5(b'password')\n"
        )

        analysis = SemgrepService().analyze_repository(str(target_dir))

        # Normalize away Semgrep's local-config namespace prefix (see
        # _check_ids docstring above) before comparing.
        rule_ids = [f.rule_id.rsplit(".", 1)[-1] for f in analysis.findings]
        assert "weak-hash-md5-sha1" in rule_ids
        assert "A02:2021" in analysis.owasp_categories
        assert analysis.total_findings >= 1